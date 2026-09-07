# VULN-001: Off-by-one OOB write in GetDLLVersion — SKIPPED

## 跳过原因

`GetDLLVersion(buffer, buflen)` 是 `replaygaindll.c` 中的一个 **DLL 导出函数**（见 `replaygaindll.def` 第17行），仅供外部调用方（caller application）直接调用，mp3gain 主程序自身从不调用该函数。

通过 `grep` 确认，整个 mp3gain 源码树中 `GetDLLVersion` 只在以下两处出现：
- `replaygaindll.c:254` — 函数定义
- `replaygaindll.def:17` — DLL 导出声明

**mp3gain 二进制处理 MP3 文件的任何执行路径都无法到达 `GetDLLVersion`。**

## 触发该漏洞的唯一方式

需要编写一个 caller 程序，直接调用 `GetDLLVersion(buf, N)` 并传入一个精确大小的缓冲区。这违反了本项目的硬性规则（"严禁自写 harness"），因此本漏洞无法通过合法途径复现。

## 结论

本漏洞命中跳过条件：**"漏洞无法通过在命令行传入构造的 MP3 文件来触发（即需要修改源码才能到达）"**，故标记为 SKIPPED。
