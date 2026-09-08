I've completed the full analysis of `image.cpp` (943 lines, read in 5 passes), traced the key call chains with Grep, and verified the `DataBuf` bounds-checking implementation. Here is my finding:

## VULN: Stack Overflow via Unbounded Recursion in printIFDStructure
- **漏洞类别**: memory-safety
- **函数**: Image::printIFDStructure()
- **行号**: 326-527 (递归调用在 462 行和 502 行)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF/JPEG/PNG/WEBP/CR2/ORF/RW2/JP2 image file
- **外部触发路径**: `exiv2 pr -pR <file>` → `TiffImage::printStructure()` → `Image::printTiffStructure()` → `Image::printIFDStructure()` → (SubIFD tag 0x014a or ExifTag 0x8769 or type==tiffIfd) → `Image::printIFDStructure(depth+1)` → … [无限递归直至栈溢出]
- **描述**: `printIFDStructure`（image.cpp:326）在处理 SubIFD（tag 0x014a）、ExifTag（tag 0x8769）或 tiffIfd 类型的 IFD 条目时（第 458–464 行），以 `depth+1` 递归调用自身，且对非 Sony 的 MakerNote（tag 0x927c）走 else 分支同样递归（第 502 行）。函数内部完全没有最大深度检测（grep 确认无 `if (depth > MAX)` 类检查）。`visits` 集合（第 324 行 static 变量）仅通过记录 `io.tell()` 位置来检测 *循环引用*（同一 IFD 条目位置被访问两次），但对于线性/树形深嵌套结构（每级 IFD 拥有不同文件偏移），`visits` 永远不会触发终止条件，递归深度随嵌套级数无限增长。`Image::max_recursion_depth_`（初始化为 1000，第 890 行）只被 XMP 解析路径使用，**从未**被 `printIFDStructure` 使用。每个函数帧在栈上占用 DataBuf(32)+多个 size_t 局部变量约 200–500 字节；一个 ~720KB 的精心构造的 TIFF 文件（约 40,000 个线性嵌套的最小 IFD，每个 IFD 仅 18 字节）即可耗尽默认 8MB 线程栈，导致栈溢出崩溃。
- **触发条件**: 攻击者构造一个包含深度线性嵌套 SubIFD 链的 TIFF 文件（IFD₀→IFD₁→…→IFD_N），每级 IFD 含一个 SubIFDs（0x014a）条目或 ExifTag（0x8769）条目指向下一级，且各级使用不同的文件偏移。受害者对该文件执行结构打印（使用 kpsRecursive 选项）：`exiv2 pr -pR crafted.tiff` 或调用了 `printStructure(kpsRecursive)` 的任何应用程序（包括服务端批量图片处理工具）。
- **安全影响**: 进程因栈溢出崩溃（段错误），造成拒绝服务（DoS）。在有 ASLR 和栈保护（stack canary）的现代系统上基本只能利用为崩溃/DoS；若目标程序禁用了栈保护，栈溢出理论上可能覆盖返回地址，但实际利用为 RCE 的可能性较低。

<!-- AUDIT_PROMPT_VERSION: 1 -->
