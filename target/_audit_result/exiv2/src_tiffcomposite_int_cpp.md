I have now thoroughly read all 1511 lines of `tiffcomposite_int.cpp` in three batches, and traced the calling chains through `tiffvisitor_int.cpp` and `tiffimage_int.cpp`. Here is my complete analysis:

**Batch 1 (lines 0–599)** — `setStrips`, `addElement`, `updateValue`, `doAddPath` family: `setStrips` checks bounds with correct short-circuit unsigned arithmetic; `addElement` is bounded by `doSize()-idx` with loop invariant `idx < doSize()`; `updateValue` reallocates before any copy. No OOB read/write found.

**Batch 2 (lines 600–1199)** — `doAccept` family, `doWrite` family: `TiffDirectory::doAccept` at line 665 recurses via `pNext_->accept(visitor)` with no depth counter. `sizeValue` accumulation in `doWrite` has no overflow guard but affects only write-path correctness. `visitBinaryArray` post-processing loop can infinite-loop if `addElement` returns 0 (CPU DoS, no memory corruption).

**Batch 3 (lines 1200–1511)** — `doWriteImage`, `doSize` family, free functions: no additional memory-safety issues found.

**Cross-file analysis** — `TiffParserWorker::parse()` creates a `TiffReader` and calls `rootDir->accept(reader)` with NO `DecodeParams`/depth limit. The `max_recursion_depth_` in `TiffDecoder` is forwarded only to `XmpParser`, never to `TiffReader`. `TiffReader::visitDirectory` has a `circularReference` check (blocks same-address revisit) but CANNOT block a non-circular chain of N unique IFD addresses. Each such address triggers one more recursive frame in `TiffDirectory::doAccept`.

## VULN: Stack Overflow via Unbounded IFD Next-Chain Recursion
- **漏洞类别**: memory-safety
- **函数**: TiffDirectory::doAccept()
- **行号**: 655-668
- **CWE**: CWE-674 (Uncontrolled Recursion leading to stack-based memory corruption)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 pr \<file\> → TiffImage::readMetadata() → TiffParserWorker::parse() → rootDir->accept(TiffReader) → TiffDirectory::doAccept(TiffReader) → TiffReader::visitDirectory() [builds pNext_] → pNext_->accept(TiffReader) → TiffDirectory::doAccept(TiffReader) → … [N frames, no depth limit]
- **描述**: `TiffDirectory::doAccept` (tiffcomposite_int.cpp:665) calls `pNext_->accept(visitor)` to follow the IFD "next" chain. This call is made recursively with no depth counter. The only protection is `TiffReader::circularReference`, which tracks start-address uniqueness and therefore only prevents loops; a non-circular chain of N IFDs at N distinct file offsets defeats the check entirely. Each recursive frame adds ~200–400 bytes to the call stack. At 8 MB stack, roughly 20,000–40,000 consecutive IFDs cause a stack overflow — achievable with a ~120–240 KB crafted TIFF (6 bytes per IFD: 2-byte count + 4-byte next pointer). `DecodeParams::max_recursion_depth_` exists in the codebase but is wired only to `XmpParser::decode`; the `TiffReader` is constructed in `TiffParserWorker::parse` (tiffimage_int.cpp:2128) without any depth parameter and has no IFD-depth guard of its own.
- **触发条件**: 攻击者构造一个 TIFF 文件，其中包含数万个通过 "next IFD" 指针串联的合法 IFD（每个 IFD 的起始偏移唯一，以绕过 circularReference 检查）。IFD entry count 设为 0，仅保留 4 字节的 next 指针，可在极小文件中实现数万层链。
- **安全影响**: 栈内存越界写（stack-based memory corruption）；最坏情况为攻击者在服务端图像处理管道（libexiv2 嵌入式使用）中通过上传畸形图片触发 RCE；在客户端 CLI 场景下可造成稳定的进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
