## VULN:
- **漏洞类别**: Stack Overflow via Uncontrolled Recursion (CWE-674)
- **函数**: `Image::printIFDStructure`
- **行号**: src/image.cpp:458–464
- **CWE**: CWE-674
- **CVSS v3.1**: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 7.5 HIGH
- **严重程度**: HIGH
- **攻击向量**: 攻击者提供一个精心构造的 TIFF 文件；任何调用 `printStructure(kpsRecursive)` 的程序（CLI `exiv2 -pt`、嵌入 exiv2 的服务端图像处理流水线）均可触发。
- **外部触发路径**: `exiv2 -pt <crafted.tiff>` → `TiffImage::printStructure(kpsRecursive, depth=0)` → `printTiffStructure(io, out, kpsRecursive, 0)` → `printIFDStructure(io, out, kpsRecursive, offset=8, ..., depth=0)` → 遇到 IFD 条目 tag=0x8769(ExifIFD)/0x014a(SubIFD)/type==tiffIfd 时递归调用 `printIFDStructure(..., depth+1)` → 无限深度递归，最终栈耗尽崩溃（SIGSEGV）
- **描述**: `printIFDStructure`（image.cpp:326）在 `kpsRecursive` 模式下，遇到 tag 0x8769、0x014a 或 type==tiffIfd 的 IFD 条目时（image.cpp:458），对每个 `count` 元素递归调用自身，深度加一（image.cpp:463）。函数内部对递归深度没有任何上限检查。静态变量 `visits`（image.cpp:324）仅在 `depth==1` 时清空（image.cpp:328），用于检测环路，但无法限制线性链的深度：一个包含 N 个不同偏移量的线性嵌套 IFD 链（每个 IFD 通过 tag 0x8769 LONG 指向下一个，无重复偏移）可绕过 `visits` 集合的环路检测，使递归深度达到 N 级。构造约 32,000 层嵌套（文件大小约 576 KB，每个 IFD=2+12+4=18 字节）即可耗尽典型 8 MB 线程栈，导致进程崩溃。
- **触发条件**: 
  1. 调用方使用 `kpsRecursive` 选项（exiv2 CLI 的 `-pt` 参数或等效 API 调用）。
  2. 输入为合法 TIFF 文件头 + 约 32,000 个链式 IFD，每个 IFD 含一个 tag=0x8769、type=LONG、count=1、value=下一IFD偏移量的条目。每个 IFD 偏移唯一（线性链），不触发 `visits` 环路检测。总文件约 576 KB，完全可行。
- **安全影响**: 进程因栈溢出收到 SIGSEGV 崩溃，造成拒绝服务（DoS）。若 exiv2 嵌入于无守护进程重启的服务端图像处理流水线，可导致持续服务中断。在无守护页保护的环境（罕见）中存在潜在控制流劫持风险（CWE-121），但通常影响为崩溃级 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
