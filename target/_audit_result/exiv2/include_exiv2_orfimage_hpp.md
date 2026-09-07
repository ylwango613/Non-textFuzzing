I have now thoroughly analyzed the ORF image stack, all key code paths, and supporting infrastructure. Let me write the final structured report.

## VULN: Unbounded Recursion Stack Overflow in printIFDStructure via OrfImage::printStructure
- **漏洞类别**: memory-safety
- **函数**: Image::printIFDStructure()
- **行号**: 326-527 (image.cpp), 赋值路径经过 orfimage.cpp:67
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file
- **外部触发路径**: `exiv2 pr -pRS <crafted.orf>` → `OrfImage::printStructure(out, kpsRecursive, depth)` (orfimage.cpp:67) → `Image::printTiffStructure(io, out, kpsRecursive, depth)` (image.cpp:541) → `Image::printIFDStructure(io, out, kpsRecursive, start, bSwap, c, depth)` (image.cpp:326) → [entry with tag=0x8769/0x014a or type==tiffIfd] → `Image::printIFDStructure(io, out, kpsRecursive, offset_inner, bSwap, c, depth+1)` (image.cpp:462) → 无限深度递归
- **描述**: `printIFDStructure` 在 `option == kpsRecursive` 时，对标签 0x8769（ExifTag）、0x014a（SubIFDs）和 type==tiffIfd 的 IFD 条目执行递归调用（image.cpp:459–464），且无任何最大递归深度限制。函数内部仅有一个基于文件偏移的 `visits` 集合用于检测循环引用（image.cpp:324, 354–357），但该检测只能防止同一文件位置被重复访问，无法限制非循环的深度嵌套结构。递归深度无上界，深度嵌套的 IFD 链会逐层消耗栈帧，最终导致进程栈耗尽（SIGSEGV）。
- **触发条件**: 攻击者构造一个 ORF 文件，其 IFD0 包含一个 ExifTag（0x8769）条目，指向一个新的 IFD；该 IFD 同样包含 ExifTag 指向下一个 IFD，形成 N 层非循环嵌套链（每个 IFD 位于文件中唯一的偏移处，绕过 visits 集合的循环检测）。N ≈ 数千层即可耗尽默认 8MB 栈空间（每栈帧约 200–400 字节），文件大小约数十 KB 即可实现。用户运行 `exiv2 -pRS <file>` 或任何调用 `printStructure(kpsRecursive)` 的程序即可触发。
- **安全影响**: 最坏情况下进程崩溃（DoS/SIGSEGV）。在无栈保护页（stack guard page）的嵌入式或特定配置环境中，递归占用的栈帧可能覆盖相邻内存区域（如堆、BSS 段），理论上可升级为远程代码执行（RCE）。若 exiv2 作为图像处理服务的后端组件，则攻击者可通过上传畸形 ORF 文件无需任何特权即可远程崩溃服务进程。

<!-- AUDIT_PROMPT_VERSION: 1 -->
