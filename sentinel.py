#!/usr/bin/env python3
"""
Claude Sentinel —— 访问 Claude 的出口 IP 哨兵（UserPromptSubmit hook）

每次提交 prompt 前运行：探测“你实际访问 Claude 的出口公网 IP”及其所在地区，
按所选模式决定放行 / 阻断；被阻断时 prompt 不会发给模型。

== 三种模式（优先级从高到低：--ip > --region > 默认） ==
1) 固定 IP（--ip <IP[,IP...]>）：只有出口 IP 精确命中列表中任意一个才放行，
   否则一律阻断（不再看地区，该列表即为 IP 白名单）。
   例：  python sentinel.py --ip 1.2.3.4
         python sentinel.py --ip 1.2.3.4,5.6.7.8
2) 地区白名单（--region <ISO[,ISO...]>）：仅当出口地区在指定列表内才放行，
   不在则阻断（与默认模式相反：默认是黑名单，这里是白名单）。
   例：  python sentinel.py --region US
         python sentinel.py --region US,JP,SG
3) 默认（地区黑名单）：地区落在受限区(默认 CN/HK)即阻断，其余放行。

== 探测方式：向 Claude 同主机名发 Cloudflare trace ==
分流(按域名/规则分线路)场景下，api.ipify.org 走的是它自己匹配到的线路，
未必和 api.anthropic.com 同路。本脚本改为向 Claude 用的同一主机名发探测：
    https://api.anthropic.com/cdn-cgi/trace
api.anthropic.com 在 Cloudflare 后面，Cloudflare 对所有被代理域名都提供
/cdn-cgi/trace，回显目标边缘看到的你的出口 IP(ip=)和国家码(loc=)。
由于主机名与真实 Claude 流量一致，你的分流规则会做出相同的路由决策：
  - ip=  就是“访问 Claude 的真实出口 IP”
  - loc= 是 Cloudflare 对该 IP 判定的国家码 —— 直接拿来做地区判定，
         无需本地 GeoIP 库。

输出语义（均 exit 0 + JSON 到 stdout）：
  放行 -> additionalContext 注入 Claude 上下文（由 Claude 在回复开头展示状态行）
  阻断 -> {"decision":"block","reason":"..."}，prompt 被丢弃。
         CLI 会显示 reason 文本；desktop 不渲染它（#10964 同类 UI 缺陷，
         exit 2 + stderr 同样不渲染），故 desktop 上另弹系统级提示窗兜底。
颜色：Claude Code 各端不可靠渲染 ANSI，用 🟢/🔴 emoji 传达绿/红状态。
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.parse

# ============================== 配置区 ==============================
# 被拦截的国家/地区 ISO 代码。需要可加 "MO"(澳门) / "TW"(台湾)
BLOCKED_COUNTRIES = {"CN", "HK"}

HTTP_TIMEOUT = 6  # 每个探测请求的超时（秒）

# 当无法确定出口 IP 或地区时（断网 / trace 全挂 / loc 为空）：
#   True  -> 阻断 (fail-closed，合规优先，最保险)
#   False -> 放行 (fail-open，网络抖动时不会把你锁死)
# 注：--ip / --region 模式下，无论此项如何，拿不到出口 IP（或 --region 下
# loc 为空）一律阻断——白名单无法核对就不该放行。
FAIL_CLOSED = True

# Claude 实际访问的主机。向它的 Cloudflare /cdn-cgi/trace 探测，
# 分流规则会对它做出和真实 Claude 流量一致的路由。
# 若设置了 ANTHROPIC_BASE_URL（自定义网关/代理），优先探测它的主机名。
CLAUDE_TRACE_HOSTS = ["api.anthropic.com", "claude.ai"]

# 放行时检测结果注入 Claude 上下文；此开关再让 Claude 在回复开头原样输出
# 状态行（CLI / desktop 都能显示）。不用 systemMessage——desktop 不渲染它（#50542）。
STATUS_PREPEND_IN_REPLY = True

# 阻断时的用户反馈，按调用方分流（CLAUDE_CODE_ENTRYPOINT 实测值）：
#   desktop（claude-desktop）-> 弹系统级提示窗。desktop 不渲染 decision:block
#     的 reason（实测，同类 UI 缺陷见 #10964），弹窗是唯一保证可见的通道。
#     Windows 用 user32 MessageBoxTimeoutW（置顶警告框，自动关）；
#     macOS 用 osascript display dialog（caution 图标，giving up after 自动关）。
#   CLI（cli / sdk-cli 等其他值）-> 不弹窗，reason 文本会正常显示在终端。
# decision:block JSON 两端都输出——它才是真正执行阻断的东西。
NOTIFY_ON_BLOCK = True            # 总开关；False 则任何端都不弹窗
NOTIFY_ONLY_DESKTOP = True        # True: 仅 desktop 弹窗；False: 不分端都弹
NOTIFY_TIMEOUT_MS = 15000  # 弹窗自动关闭时间(毫秒)；0 = 不自动关，需手动点掉
# ===================================================================

# Windows 下重定向流默认走本地编码(cp936)，会让中文乱码、JSON 解析失败。强制 UTF-8。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass


def log(msg):
    print(f"[claude-sentinel] {msg}", file=sys.stderr)


def parse_args():
    p = argparse.ArgumentParser(
        prog="sentinel.py",
        description="Claude Sentinel: 你的IP防探头哨兵",
    )
    p.add_argument(
        "--ip",
        metavar="IP[,IP...]",
        default=None,
        help="固定 IP 模式：仅当访问 Claude 的出口 IP 精确命中列表中任意一个时放行，"
             "否则阻断（不再看地区）。逗号分隔，如 --ip 1.2.3.4 或 --ip 1.2.3.4,5.6.7.8。",
    )
    p.add_argument(
        "--region",
        metavar="ISO[,ISO...]",
        default=None,
        help="地区白名单模式：仅当出口地区在指定列表内才放行，否则阻断。"
             "ISO 3166-1 两位码，逗号分隔，如 --region US 或 --region US,JP,SG。",
    )
    # hook 可能不带参数调用；用 parse_known_args 容忍未知参数，避免误退出。
    args, _ = p.parse_known_args()
    return args


def _http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return r.read().decode(errors="replace")


def trace_hosts():
    hosts = []
    base = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    if base:
        try:
            h = urllib.parse.urlsplit(
                base if "://" in base else "https://" + base).hostname
            if h:
                hosts.append(h)
        except Exception:
            pass
    for h in CLAUDE_TRACE_HOSTS:
        if h not in hosts:
            hosts.append(h)
    return hosts


def get_claude_egress():
    """返回 (ip, loc, colo, via)。ip=访问 Claude 的真实出口 IP；
    loc=Cloudflare 对该 IP 判定的国家码；colo=接入的 Cloudflare 边缘机房
    （IATA 三字码，反映出口大致方位，仅展示不参与判定）；via=数据来源。"""
    for h in trace_hosts():
        try:
            body = _http_get(f"https://{h}/cdn-cgi/trace")
            kv = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
            ip = (kv.get("ip") or "").strip()
            loc = (kv.get("loc") or "").strip().upper()
            colo = (kv.get("colo") or "").strip().upper()
            if ip:
                return ip, loc, colo, f"trace:{h}"
        except Exception:
            continue

    return None, "", "", "none"


NOTIFY_TITLE = "Claude Sentinel — prompt 已阻断"


def is_desktop():
    """hook 是否由 Claude Code desktop 调起。
    实测：desktop -> claude-desktop；终端 CLI -> cli；claude -p/SDK -> sdk-cli。
    注意：该变量无官方文档背书（区分界面是 open feature request #28144），
    若未来 desktop 改值，最多退化为'不弹窗'，阻断本身不受影响。"""
    return os.environ.get("CLAUDE_CODE_ENTRYPOINT") == "claude-desktop"


def notify_block(text):
    """弹系统级提示窗（detached 子进程，不阻塞 hook 退出）。
    Windows 用 MessageBoxTimeoutW（user32 未公开但长期稳定，支持超时自动关闭）；
    macOS 用 osascript display dialog（giving up after 自动关闭）。"""
    if not NOTIFY_ON_BLOCK:
        return
    if NOTIFY_ONLY_DESKTOP and not is_desktop():
        return
    try:
        import subprocess
        quiet = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
        if sys.platform == "win32":
            child = (
                "import ctypes;"
                "ctypes.windll.user32.MessageBoxTimeoutW("
                f"0, {text!r}, {NOTIFY_TITLE!r}, "
                f"0x30 | 0x40000, 0, {int(NOTIFY_TIMEOUT_MS)})"  # 0x30=警告图标 0x40000=置顶
            )
            subprocess.Popen(
                [sys.executable, "-c", child],
                creationflags=0x00000008 | 0x08000000,  # DETACHED_PROCESS | CREATE_NO_WINDOW
                **quiet,
            )
        elif sys.platform == "darwin":
            # AppleScript 2.0+ 字符串支持 \n/\"/\\ 转义
            def as_str(s):
                return '"' + s.replace("\\", "\\\\").replace('"', '\\"') \
                              .replace("\n", "\\n") + '"'
            script = (
                f"display dialog {as_str(text)} with title {as_str(NOTIFY_TITLE)} "
                f'buttons {{"OK"}} default button 1 with icon caution'
            )
            secs = int(NOTIFY_TIMEOUT_MS / 1000)
            if secs > 0:
                script += f" giving up after {secs}"
            subprocess.Popen(["osascript", "-e", script],
                             start_new_session=True, **quiet)
    except Exception:
        pass  # 弹窗失败不影响阻断本身


def decide_block(reason, ip=None, loc=None, colo=None):
    node = f" | 节点: {colo}" if colo else ""
    status_line = f"🌐 当前IP: {ip or '未知'} | 地区: {loc or '未知'}{node} | 🔴 阻断"
    # 阻断用 exit 0 + JSON {"decision":"block","reason":...}，而非 exit 2 + stderr：
    # desktop 版不渲染 exit2 的 stderr，只显示干巴巴的 "hook error" 标签（#10964）。
    # reason 在 CLI 正常显示；desktop 实测也不渲染 reason，故同时弹系统级提示窗兜底。
    notify_block(f"{status_line}\n\n{reason}")
    sys.stdout.write(json.dumps(
        {"decision": "block", "reason": f"{status_line}\n{reason}"},
        ensure_ascii=False))
    sys.exit(0)


def decide_allow(ip=None, loc=None, colo=None, via=None, mode=None, regions=None):
    node = f" | 节点: {colo}" if colo else ""
    status_line = f"🌐 当前IP: {ip or '未知'} | 地区: {loc or '未知'}{node} | 🟢 通过"
    if mode == "fixip":
        gate = f"出口 IP 命中指定放行 IP {ip}"
    elif mode == "region":
        gate = f"出口地区 {loc} 命中放行地区 {'/'.join(sorted(regions or []))}"
    else:
        gate = f"受限区 {'/'.join(sorted(BLOCKED_COUNTRIES))} 未命中"
    ctx = (
        f"[出口IP哨兵] 本回合已检测访问 Claude 的出口 IP："
        f"ip={ip or '未知'}, 地区={loc or '-'}(Cloudflare loc), "
        f"节点={colo or '-'}, via={via or '-'} → 放行（{gate}）。"
    )
    if STATUS_PREPEND_IN_REPLY:
        ctx += (
            f"\n请在你本条回复的最开头单独一行、原样输出以下状态行，然后空一行再正常作答"
            f"（仅此一行，勿改写、勿添加解释）：\n{status_line}"
        )
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": ctx,
        },
    }, ensure_ascii=False))
    sys.exit(0)


def main():
    args = parse_args()
    allowed_ips = {x.strip() for x in (args.ip or "").split(",") if x.strip()}
    allowed_regions = {r.strip().upper() for r in (args.region or "").split(",") if r.strip()}

    # 读掉 stdin 上的 prompt 负载（决策用不到，但要把管道排空）
    try:
        sys.stdin.read()
    except Exception:
        pass

    ip, loc, colo, via = get_claude_egress()
    if not ip:
        # 拿不到出口 IP：白名单模式(--ip/--region)无法核对 -> 一律阻断
        if allowed_ips:
            decide_block(
                f"无法确定访问 Claude 的出口 IP，无法核对是否在放行 IP 白名单 "
                f"{'/'.join(sorted(allowed_ips))}（trace 失败, via {via}）-> 阻断。")
        if allowed_regions:
            decide_block(
                f"无法确定访问 Claude 的出口 IP/地区，无法核对是否在放行地区 "
                f"{'/'.join(sorted(allowed_regions))}（trace 失败, via {via}）-> 阻断。")
        if FAIL_CLOSED:
            decide_block("无法确定访问 Claude 的出口 IP（trace 失败）-> 阻断 (fail-closed)")
        log("无法确定访问 Claude 的出口 IP -> 放行 (fail-open)")
        decide_allow(via=via)

    loc = (loc or "").upper()

    # ===== 固定 IP 模式：精确命中白名单任意一个才放行（优先级最高） =====
    if allowed_ips:
        if ip in allowed_ips:
            decide_allow(ip=ip, loc=loc, colo=colo, mode="fixip")
        decide_block(
            f"访问 Claude 的出口 IP {ip} 不在放行 IP 白名单 "
            f"{'/'.join(sorted(allowed_ips))} 内（via {via}）。本条 prompt 未发送给 Claude。",
            ip=ip, loc=loc, colo=colo,
        )

    # ===== 地区白名单模式：出口地区不在指定列表内即阻断 =====
    if allowed_regions:
        if not loc:
            decide_block(
                f"无法判定出口 IP {ip} 的地区（loc 为空, via {via}），"
                f"无法核对是否在放行地区 {'/'.join(sorted(allowed_regions))} -> 阻断。",
                ip=ip, colo=colo,
            )
        if loc in allowed_regions:
            decide_allow(ip=ip, loc=loc, colo=colo, mode="region", regions=allowed_regions)
        decide_block(
            f"访问 Claude 的出口 IP {ip} 判定地区为 {loc}，不在放行地区 "
            f"{'/'.join(sorted(allowed_regions))} 内（via {via}）。本条 prompt 未发送给 Claude。",
            ip=ip, loc=loc, colo=colo,
        )

    # ===== 默认：地区哨兵 =====
    # 命中判定：Cloudflare loc 落在受限区即拦
    if loc in BLOCKED_COUNTRIES:
        decide_block(
            f"访问 Claude 的出口 IP {ip} 判定地区为 {loc}，位于受限区"
            f"（{'/'.join(sorted(BLOCKED_COUNTRIES))}, via {via}）。本条 prompt 未发送给 Claude。",
            ip=ip, loc=loc, colo=colo,
        )

    # 地区未知（loc 为空）-> 按失败策略处理
    if not loc:
        if FAIL_CLOSED:
            decide_block(f"无法判定出口 IP {ip} 的地区（loc 为空, via {via}）-> 阻断 (fail-closed)",
                         ip=ip, colo=colo)
        log(f"出口 IP {ip} 地区未知（via {via}）-> 放行 (fail-open)")
        decide_allow(ip=ip, colo=colo, via=via)

    # 放行：把检测结果作为 JSON 输出（systemMessage 给用户、additionalContext 给 Claude）
    decide_allow(ip=ip, loc=loc, colo=colo, via=via)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        # 脚本自身出错（代码 bug、环境异常等）时 fail-closed：
        # 若任由异常退出（exit 1），Claude Code 会视为"非阻塞错误"而静默放行，
        # 等于敞开。这里兜底输出 block，宁可误拦也不漏放。
        try:
            notify_block(f"Claude Sentinel 内部错误，已 fail-closed 阻断\n\n{e!r}")
            sys.stdout.write(json.dumps(
                {"decision": "block",
                 "reason": f"🌐 Claude Sentinel 内部错误（{e!r}）-> 阻断 (fail-closed)。"
                           f"请检查 ~/.claude/hooks/sentinel.py。"},
                ensure_ascii=False))
        except Exception:
            pass
        sys.exit(0)
