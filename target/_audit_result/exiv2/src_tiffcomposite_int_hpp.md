Based on my thorough analysis of `tiffcomposite_int.hpp`, `tiffcomposite_int.cpp`, and `tiffvisitor_int.cpp`, I've traced all critical code paths including `readTiffEntry`, `visitDirectory`, `visitSubIfd`, `visitBinaryArray`, `addElement`, `setStrips`, and `decodeCanonAFInfo`. Here is my final assessment:

**Group 1 (lines 1–600 hpp + cpp constructor/accessor section):** Clean interface and constructors. `setData`, `setStrips` bounds checks look correct.

**Group 2 (`readTiffEntry` lines 1232–1332 of tiffvisitor):** Bounds checking in place — Safe::add, `pLast_` comparisons prevent OOB.

**Group 3 (`visitDirectory` + `circularReference`):** The circular-reference guard only prevents *same-address* cycles; linear next-IFD chains of distinct addresses are NOT bounded — confirmed unbounded recursion.

**Group 4 (`visitBinaryArray`/`addElement`):** Infinite loop possible if `addElement` returns 0, but `Tag::all` entries in the structure table prevent this for properly registered groups.

**Group 5 (`decodeCanonAFInfo`):** `uint16_t count` overflows with large `nPoints`, bypassing validity check — but `vector::at()` throws `std::out_of_range` before OOB memory access, converting this to DoS-only.

## VULN: Stack Overflow via Unbounded IFD Next-Pointer Chain Recursion
- **漏洞类别**: memory-safety
- **函数**: TiffDirectory::doAccept()
- **行号**: 655-668 (tiffcomposite_int.cpp)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 pr \<file\> -> Image::readMetadata() -> TiffParser::decode() -> pRoot->accept(reader) -> TiffDirectory::doAccept(reader) -> visitor.visitDirectory(this) [creates pNext_] -> pNext_->accept(visitor) [recursive call] -> TiffDirectory::doAccept [level N] -> ... -> stack exhaustion
- **描述**: `TiffDirectory::doAccept()` at line 664 calls `pNext_->accept(visitor)` recursively for each IFD in the next-pointer chain with no recursion depth limit. The `circularReference()` guard (tiffvisitor_int.cpp:1040–1050) only detects cycles where the same `const byte* start` address is revisited; a linear chain of IFDs at strictly distinct file offsets fully bypasses this check. Each level of the chain pushes an additional C++ stack frame for `doAccept`, `accept`, and `visitDirectory`, consuming ~200–500 bytes of stack per IFD level. With Linux's default 8 MB stack, approximately 16,000–40,000 linked IFDs trigger a stack overflow (SIGSEGV), and on platforms lacking guard pages the overflow can corrupt adjacent heap or BSS memory.
- **触发条件**: 构造一个 TIFF 文件：在 IFD0 的 next-IFD 字段写入指向 IFD1 的偏移，IFD1 的 next-IFD 再指向 IFD2，……每个 IFD 至少含一个 12 字节 entry 加 2 字节 count 加 4 字节 next = 18 字节。一个约 720 KB 的文件（40,000 个 IFD × 18 字节）即可溢出默认 8 MB 栈；每个 IFD start 地址唯一（递增偏移），规避 circularReference 检查。
- **安全影响**: 最差情形为进程崩溃 (SIGSEGV)，导致拒绝服务。在无栈守卫页的环境（嵌入式/某些容器）中，深度栈溢出可覆盖相邻堆数据或返回地址，存在远程代码执行理论风险；当 exiv2 作为服务端图像处理库时攻击向量升级为网络可达，危害程度显著提升。

<!-- AUDIT_PROMPT_VERSION: 1 -->
