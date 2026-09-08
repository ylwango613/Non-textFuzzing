Based on my thorough analysis of `orfimage.cpp` and its full call chain — including `orfimage_int.cpp`, `tiffimage_int.cpp`, `tiffvisitor_int.cpp`, `tiffcomposite_int.cpp`, and `image.cpp` — here is my final report:

## VULN: Unbounded Recursion Stack Overflow in printIFDStructure via Crafted ORF ExifTag Chain
- **漏洞类别**: memory-safety
- **函数**: Image::printIFDStructure()
- **行号**: 326-527 (src/image.cpp), 触发入口 OrfImage::printStructure() 在 src/orfimage.cpp:54-68
- **CWE**: CWE-674 (Uncontrolled Recursion) → CWE-121 (Stack-based Buffer Overflow via stack exhaustion)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted ORF image file
- **外部触发路径**: `image->printStructure(out, kpsRecursive)` (library API) 或 Debug 构建下 `exiv2 -pR <file>` → `OrfImage::printStructure()` (orfimage.cpp:67) → `Image::printTiffStructure()` (image.cpp:541) → `Image::printIFDStructure(depth=0)` (image.cpp:326) → per entry: `printIFDStructure(depth=1)` → `printIFDStructure(depth=2)` → … (无限递归)
- **描述**: `Image::printIFDStructure()` 在处理 `kpsRecursive` 选项时，当遇到 ExifTag（tag=0x8769）、SubIFD（tag=0x014a）或 tiffIfd 类型条目时，在 image.cpp:462 处递归调用自身，传入 `depth+1`。该函数没有任何递归深度上限检查。虽然使用了静态变量 `visits`（类型为 `std::set<size_t>`）来记录已访问的 IFD 条目文件偏移以检测循环引用，但该机制仅能阻止循环（cycle），无法阻止长链（chain）：当攻击者构造一个 ORF 文件，令每个 IFD 都通过 ExifTag 指向下一个处于全新文件偏移的 IFD（无重复），所有位置均为唯一值，`visits` 永远不会触发 `throw`，递归深度随链的长度线性增长，最终导致栈空间耗尽（stack overflow/SIGSEGV）。`kpsRecursive` 是 `PrintStructureOption` 公开枚举的一部分（image.hpp:40），可通过库 API 无限制地调用。
- **触发条件**: 攻击者构造一个合法 ORF 头（`II\x52\x4F` + root-IFD-offset）的文件，其中包含 N 个 IFD 的线性链，每个 IFD 含一个 ExifTag（0x8769，type=LONG，count=1）指向下一个 IFD，所有 IFD 地址各异（约每个 18 字节）。约 20,000 层链（~360 KB 文件）可在默认 8 MB 栈的进程上触发崩溃。调用方须以 `kpsRecursive` 选项调用 `printStructure()`（Release CLI 以 `#ifdef NDEBUG` 禁用该选项，但库 API 始终可用）。
- **安全影响**: 处理攻击者控制文件的服务进程或工具崩溃（DoS）。在无栈保护的配置下，栈溢出有潜在的任意代码执行风险；但在具有 stack-guard page 的现代系统上最坏情况为进程终止。

<!-- AUDIT_PROMPT_VERSION: 1 -->
