Now I have enough data to synthesize the full report. The traversal in `TiffDirectory::doAccept` → `TiffSubIfd::doAccept` is recursive, and `TiffReader` has no depth counter — only a `circularReference()` flat-pointer check that prevents loops but does nothing against a long linear chain of distinct IFDs.

## VULN: Uncontrolled Recursion in TiffReader IFD/SubIFD Traversal Leading to Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: TiffDirectory::doAccept() / TiffSubIfd::doAccept() / TiffReader::visitDirectory() / TiffReader::visitSubIfd()
- **行号**: tiffcomposite_int.cpp:655-668, 670-677; tiffvisitor_int.cpp:1066-1138, 1140-1178
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 pr <file> -> TiffImage::readMetadata() -> TiffParserWorker::decode() -> TiffParserWorker::parse() -> rootDir->accept(reader) [line 2129 tiffimage_int.cpp] -> TiffDirectory::doAccept(reader) -> component->accept(reader) [TiffSubIfd] -> TiffSubIfd::doAccept(reader) -> TiffReader::visitSubIfd() [creates child TiffDirectory at attacker-controlled offset] -> child->accept(reader) -> TiffDirectory::doAccept(reader) -> … [unbounded recursion]
- **描述**: `TiffReader` constructs the TIFF composite tree while simultaneously traversing it via the Visitor pattern. `TiffDirectory::doAccept` (tiffcomposite_int.cpp:655) iterates its child components and calls `component->accept(visitor)` recursively. `TiffSubIfd::doAccept` (line 670) calls `ifd->accept(visitor)` for each child `TiffDirectory`. The only protection is `TiffReader::circularReference()` (tiffvisitor_int.cpp:1040), which uses a `std::map<const byte*, IfdId>` to detect re-visiting of the same file offset — this prevents cycles but does **not** bound the depth of a linear chain. `TiffReader` has no recursion-depth counter (unlike `TiffDecoder`, which carries `max_recursion_depth_` only for XMP). A crafted TIFF/JPEG embedding a chain of N distinct Sub-IFDs at N different file offsets drives N levels of C++ call-stack recursion. Each unique start pointer passes the circular-reference check and adds 4–6 stack frames per level; at ~1,000 bytes/frame, 8,192 levels exhaust the typical 8 MB Linux thread stack, crashing the process with SIGSEGV.
- **触发条件**: 构造一个 TIFF/JPEG 文件，其中包含一条由数千个不同文件偏移量处的 Sub-IFD 组成的线性链：IFD₀ 含一个 SubIFD 指向偏移量₁的 IFD₁，IFD₁ 含一个 SubIFD 指向偏移量₂的 IFD₂，如此循环。所有偏移量各不相同（通过 circularReference 检查），每个 IFD 只需约 18 字节（count=1 + 12 字节条目 + 4 字节 next=0）。100 KB 文件即可包含约 5,000 层，足以耗尽 8 MB 默认栈空间。
- **安全影响**: 任意攻击者可向用户发送一个恶意 TIFF/JPEG 文件（或托管在网页/邮件中），当用户用 exiv2 或任何嵌入了 exiv2 库的应用程序处理该文件时，进程崩溃（DoS）。在栈保护缺失或可绕过的条件下（如旧版本 exiv2 或第三方嵌入场景），深度递归引发的栈指针越界可能覆盖相邻内存区域，进而导致控制流劫持（潜在 RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
