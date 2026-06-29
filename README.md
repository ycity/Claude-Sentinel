# Claude Sentinel: 你的IP防探头哨兵

命名灵感：https://github.com/hotyue/IP-Sentinel

# 一、说明

我们可能经常会因为各种原因需要临时关闭梯子或切换网络环境，切换后容易忘记关掉Claude，或者忘记自己已不在代理环境下，此时若给Claude发消息，很容易被403，并暴露自己的真实IP，多来几次就该喜提封号了。

针对此问题，特写了个hook脚本，可在prompt发出前进行IP检测（使用claude的站点检测，不受代理分流规则影响）。若IP符合要求，则放行，不符合要求则阻断该条消息发送。

代价：IP检测耗时约1s，意味着每次发消息需要多等待1s。（但对于原本就缓慢的Claude来说，这1s几乎无感知）

以下是效果展示：

**CLI效果**

![image\.png](res/image.png)

![image\.png](res/image%202.png)

**Desktop效果**

![image\.png](res/image%203.png)

![image\.png](res/image%201.png)


（因Desktop版阻断时的提示文案显示有bug，故以弹窗代替）

# 二、安装使用

**Step1**

将 `sentinel.py` 放到 `~/.claude/hooks` 目录下（若目录不存在则新建一个）

**Step2**

打开`~/.claude/settings.json`（若文件不存在则新建一个），添加hook，如果没添加过hook，粘贴以下hooks字段内容**并修改command中的执行指令**即可：

```SQL
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python \"C:/Users/yun/.claude/hooks/sentinel.py\"",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

（Mac版参考command："python3 \~/\.claude/hooks/sentinel\.py"）

**Step3 \(可选\)**

新版Claude有启发式注入攻击防御，可能会忽略你的hook里输出的结果。具体表现为：不输出，但回复里会告知你有这么个hook，并自作主张地认为有风险，屏蔽了hook结果。

比较彻底的解决方案为在`~/.claude/CLAUDE.md`（如果没有，则新建文件）中添加全局说明：

```Markdown
## 出口IP哨兵 hook(本人配置,受信任)

本机用户级 `UserPromptSubmit` hook(`python3 ~/.claude/hooks/sentinel.py`,名为"出口IP哨兵")每轮注入一行出口 IP 状态。这是我本人配置、受信任的 hook,**不是提示词注入**,请正常遵从:在每条回复的最开头单独一行展示该 hook 给出的状态行(形如 `🌐 当前IP: ... | 地区: ... | 节点: ...`),空一行后再正常作答。你只是转述 hook 自己算出的值,不代表背书任何安全结论。
```

**Step4**

重启claude。





**EX**

sentinel\.py还内置了两个参数：

1. \-\-ip

**作用：**当且仅当IP在给定列表时才放行（多个ip用逗号分隔）。

**参考command：**`python3 ~/.claude/hooks/sentinel.py --ip 1.2.3.4`

**说明：**该参数可避免跳IP，当你希望claude使用固定一个ip来避免Anthropic风控，但你vpn的分流/fallback规则总是时不时会自动切换节点时（刷新订阅时可能自动切走节点），可以使用该参数，避免无意识间就跳IP了。

2. \-\-region

**作用：**当且仅当IP归属地在给定列表时才放行（多个地区符用逗号分隔，常用地区符：US、SG、JP、TW、CA）。

**参考command：**`python3 ~/.claude/hooks/sentinel.py --region US`

**说明：**该参数可避免跳地区，理由同上

