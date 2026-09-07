I've now completed a thorough analysis of the codebase. Let me compile the final findings.

**Group 1 – `readTiffEntry` (tiffvisitor_int.cpp:1232-1332):** Well-protected. Count overflow guarded by `count >= 0x10000000` check and `count > SIZE_MAX / typeSize` throw. Both offset + size bounds carefully validated.

**Group 2 – `visitSubIfd` (tiffvisitor_int.cpp:1140-1177):** The potential OOB I initially suspected is mitigated: when data is truncated (size→0), `v->read(pData, 0, ...)` produces count=0 → loop never runs.

**Group 3 – `visitBinaryArray` (tiffvisitor_int.cpp:1334-1410):** Infinite loop when `addElement` returns 0, but this is DoS only, not memory corruption.

**Group 4 – `printIFDStructure` (image.cpp:326-542):** **Confirmed stack overflow.** When `option == kpsRecursive`, recursive calls at lines 462 and 502 have no depth limit. The only guard is a `static std::set<size_t> visits` that prevents revisiting the **same IO position** – but a crafted chain of N IFDs at distinct positions is unlimited. Minimum IFD: 2 + 12 + 4 = 18 bytes → a 500 KB file yields ~27,000 IFD levels → ~8.1 MB stack at ~300 B/frame → overflow.

**Group 5 – IPTC/CanonAFInfo/value.cpp:** All access paths through `vector::at()` or explicit bounds checks; no memory-safety issues.

## VULN: Uncontrolled Recursion in printIFDStructure Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: `Image::printIFDStructure()`
- **行号**: 458-503 (image.cpp), recursive calls at lines 462, 497, 502; function defined at line 326
- **CWE**: CWE-674 (Uncontrolled Recursion) → CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF image file
- **外部触发路径**: `exiv2 -pR <file>` → `TiffImage::printStructure(out, kpsRecursive, depth)` → `Image::printTiffStructure(io, out, kpsRecursive, depth)` → `Image::printIFDStructure(io, out, kpsRecursive, start, bSwap, c, depth=0)` → [for each SubIFD tag 0x014a or ExifTag 0x8769 or tiffIfd-typed entry] → recursive `Image::printIFDStructure(..., depth+1)` with no depth limit
- **描述**: 当 `option == kpsRecursive` 时，`printIFDStructure` 在 image.cpp:458-464 对每个 SubIFD（tag=0x014a）、ExifIFD（tag=0x8769）或 tiffIfd 类型的 entry，无条件进入递归调用 `printIFDStructure(..., depth+1)`。唯一的循环防护是静态集合 `visits`（image.cpp:324），它仅记录已访问的 IO 文件偏移以防止地址环回，但无法限制调用栈深度。攻击者可构造一条由 N 个不同文件偏移处的 IFD 组成的链（每个 IFD 仅包含一个 SubIFD entry 指向下一个），导致 N 层 C++ 函数调用递归、耗尽线程栈空间。最小 IFD 结构仅需 18 字节（2 字节计数 + 12 字节单条 entry + 4 字节 next 指针），一个 500 KB 的畸形 TIFF 文件即可产生约 27,000 级递归，以每帧约 300 字节的保守估计消耗 ≈ 8.1 MB 栈空间，超出典型 8 MB 栈限制，造成栈溢出崩溃。
- **触发条件**: 攻击者提供一个 TIFF 文件，其中包含一条由 N 个唯一文件偏移处的 IFD 构成的线性链，每个 IFD 包含一条 tag=0x014a（SubIFDs）或 tag=0x8769（ExifTag）的 entry 且 type=tiffIfd（偏移类型），offset 字段指向链中的下一个 IFD；受害者执行 `exiv2 -pR <file>` 触发递归解析。无需任何特殊权限。
- **安全影响**: 最坏情况下可造成远程/本地代码执行（攻击者可精确控制栈溢出覆盖的返回地址），确定结果为崩溃（DoS）；在有栈金丝雀绕过手段时可升级为 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
