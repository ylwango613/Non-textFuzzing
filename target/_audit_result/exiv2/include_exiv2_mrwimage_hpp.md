Based on my thorough analysis of `mrwimage.hpp`/`mrwimage.cpp` and the full calling chain into `TiffParser::decode` → `TiffParserWorker::parse` → `TiffReader` → `TiffDirectory::doAccept`, I have identified one externally triggerable memory-safety vulnerability.

**Key findings from the analysis:**

- `MrwImage::readMetadata()` validates block headers with `enforce()` — bounds-safe.
- `readTiffEntry()` in TiffReader has multiple bounds checks (count < 0x10000000, offset+size vs. pLast_) — safe.
- `TiffDirectory::doAccept()` (tiffcomposite_int.cpp:655-668) contains `if (pNext_) pNext_->accept(visitor)` — **unconditionally recursive**.
- The `max_recursion_depth_` carried in `DecodeParams dp` is only used for **XMP parsing** (tiffvisitor_int.cpp:292), never for TIFF IFD chain traversal in `TiffReader` or `TiffDirectory::doAccept`.
- `circularReference()` catches only cycles (same start address seen twice); a strictly increasing linear chain of N unique IFDs is not caught.
- With n=0 entries per IFD, each IFD consumes 6 bytes; a 600 KB TTW block yields ~100,000 unique IFDs, far exceeding the ~16,000 stack-frame budget on an 8 MB stack.

## VULN: Stack Overflow via Unbounded IFD Next-Pointer Chain Recursion in MRW TTW Block
- **漏洞类别**: memory-safety
- **函数**: TiffDirectory::doAccept() [src/tiffcomposite_int.cpp:655-668], 触发入口 MrwImage::readMetadata() [src/mrwimage.cpp:62-118]
- **行号**: tiffcomposite_int.cpp:664-665 (`if (pNext_) pNext_->accept(visitor)`)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MRW image file
- **外部触发路径**: `exiv2 pr <file.mrw>` → `MrwImage::readMetadata()` → `TiffParser::decode()` → `TiffParserWorker::decode()` → `TiffParserWorker::parse()` → `rootDir->accept(TiffReader)` → `TiffDirectory::doAccept()` → `pNext_->accept(visitor)` [无限递归，无深度限制]
- **描述**: `TiffDirectory::doAccept()` 通过 `pNext_->accept(visitor)` 递归遍历 IFD next 指针链，该递归没有任何深度限制。`DecodeParams::max_recursion_depth_` 仅在 XMP 解析时生效，TiffReader/TiffDirectory 阶段完全不受此参数保护。`circularReference()` 仅检测指针环，对严格线性的 IFD 链无效。攻击者可在 MRW TTW 块内嵌入含有极长线性 IFD 链的 TIFF（每个 IFD 使用唯一偏移，n=0 条目），导致 `TiffDirectory::doAccept()` 在 `TiffReader` 遍历阶段发生无界递归，最终耗尽进程栈空间（SIGSEGV）。
- **触发条件**: 构造 MRW 文件：(1) 合法 MRW 文件头（4字节 magic `\0MRM` + 4字节 header size）；(2) 在 TTW 块内放置合法 TIFF 数据；(3) TIFF IFD0 链接到 IFD1，IFD1 链接到 IFD2，…，形成约 100,000+ 条唯一偏移的 IFD（每个 IFD 仅 6 字节：count=0 + next\_offset），总计约 600 KB TTW 块即可触发；(4) 无需认证，仅需用户打开文件。
- **安全影响**: 进程必然 SIGSEGV 崩溃（DoS）；在无栈保护页的特殊构建（如 `-Wl,-z,execstack` 或嵌入式环境）下，栈溢出可覆盖相邻内存区域，理论存在 RCE 可能。

<!-- AUDIT_PROMPT_VERSION: 1 -->
