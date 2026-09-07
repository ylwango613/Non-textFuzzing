Based on my thorough analysis of the RW2 image parsing code, I have identified one confirmed memory safety vulnerability. Let me write the final report.

## VULN: Stack Overflow via Unbounded Recursion in printIFDStructure for Crafted RW2 Files
- **漏洞类别**: memory-safety
- **函数**: Image::printIFDStructure()
- **行号**: 326-528 (image.cpp), 66-80 (rw2image.cpp)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted RW2 image file
- **外部触发路径**: `exiv2 -pS <crafted.rw2>` (kpsRecursive option) → `Rw2Image::printStructure()` [rw2image.cpp:66] → `Image::printTiffStructure()` [image.cpp:529] → `Image::printIFDStructure()` [image.cpp:326] → (unbounded recursive calls via tag 0x8769/0x014a/type==tiffIfd at image.cpp:462)
- **描述**: `printIFDStructure()` 在处理 ExifTag（0x8769）、SubIFDs（0x014a）或 type==tiffIfd 的 IFD 条目时，对每个 offset 值递归调用自身（image.cpp:462: `printIFDStructure(io, out, option, offset_inner, bSwap, c, depth + 1)`），但没有任何最大递归深度检查。唯一的防护机制是 file-scope 静态集合 `visits`（image.cpp:324），它仅防止同一文件偏移被重复访问（防止循环引用），无法防止线性深链（每层 IFD 各在不同文件偏移）。当 RW2 文件包含数万层深度嵌套的 TIFF IFD 链时，调用栈将超出默认 8 MB 线程栈限制，导致栈溢出崩溃（SIGSEGV）。
- **触发条件**: 攻击者构造一个如下结构的 RW2 文件：24 字节 RW2 头（字节序标记"II"，魔数 0x0055，偏移指向 IFD0），随后排列 N 个 IFD，每个 IFD 仅含 1 个 type=tiffIfd 的条目，条目的 offset 字段指向下一个 IFD 的起始地址，形成线性嵌套链。每层 IFD 最小只需 18 字节（2字节计数+12字节条目+4字节next指针）。约 300 KB 大小的文件即可嵌套约 16,000 层，足以耗尽默认栈空间。用户以 `kpsRecursive` 结构打印选项（如 `exiv2 -pS` 或等效 API 调用）处理该文件时触发漏洞。
- **安全影响**: 可靠的进程崩溃（DoS）。在未启用栈保护（stack canary）的构建中，或通过精确控制栈帧布局，理论上可将崩溃升级为任意代码执行（RCE）。当 exiv2 作为图像浏览器、数字资产管理系统等应用的后端库时，攻击者可通过上传或分发恶意 RW2 文件导致宿主进程崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
