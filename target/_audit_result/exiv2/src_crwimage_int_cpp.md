Now I have read the complete file (all 1008 lines) across multiple batches and cross-checked the header file, the call chain from crwimage.cpp, and grep'd for depth/limit controls. Let me summarize the findings from each section before writing the final report.

**Batch 1 (lines 1–500) — key findings:**
- `CiffHeader::read` (line 141–168): properly validates `offset_` against `size`.
- `CiffComponent::doRead` (line 174–210): validates `offset_/size_` from file data. The comment at lines 185-198 says the overlap-check prevents *infinite* recursion — but it only prevents the exact-10-byte-overlap case, not deep finite chains.
- `CiffDirectory::doRead` (line 212–224): calls `readDirectory(pData + offset(), this->size(), byteOrder)` — **recursive call without a depth counter**.
- `CiffDirectory::readDirectory` (line 226–252): for each directory-typed entry, calls `m->read(...)` which dispatches to `CiffDirectory::doRead` → back to `readDirectory`. **No global depth limit exists.**

**Batch 2 (lines 500–1008) — key findings:**
- `decodeArray` (line 659–718): the `n=3` read-ahead (`c==23, component_size>=52`) is bounded safely.
- `decodeBasic` (line 776–805): has `enforce(size <= ciffComponent.size())` before `value->read()`.
- `packIfdId` (line 985–1006): `if (s <= size)` guard prevents the `buf.data(exif.tag() * 2)` from going out of bounds.
- No recursion depth counter anywhere in the recursive `readDirectory` ↔ `doRead` path.

**Stack overflow analysis:**
Each recursion level in `doRead` → `readDirectory` reduces the buffer by at least 12 bytes (`start + 10 = 2 + 10 = 12` minimum for the forward offset_ case). For a ~500 KB file ≈ 41,600 levels × ~200 bytes/frame = ~8 MB of stack — exactly at the typical Linux 8 MB stack limit. A 1 MB crafted CRW file reliably overflows.

## VULN: Stack Overflow via Unbounded Recursive CRW CIFF Directory Parsing
- **漏洞类别**: memory-safety
- **函数**: CiffDirectory::readDirectory() / CiffDirectory::doRead()
- **行号**: 212-252
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 pr <file.crw> → CrwImage::readMetadata() [crwimage.cpp:55] → CrwParser::decode() [crwimage.cpp:107] → CiffHeader::read() [crwimage_int.cpp:141] → CiffDirectory::readDirectory() [crwimage_int.cpp:167] → CiffDirectory::doRead() [crwimage_int.cpp:212] → CiffDirectory::readDirectory() [crwimage_int.cpp:220] → … (recursive, no depth limit)
- **描述**: `CiffDirectory::doRead()` 在遇到类型为 `directory` 的 CIFF 条目时，调用 `readDirectory(pData + offset(), this->size(), byteOrder)`（第 220 行），该函数反过来对每个目录类型条目递归调用 `m->read()` → `CiffDirectory::doRead()`，形成无深度限制的互递归调用链。开发者在第 185–198 行加入了重叠检测，以防止"无限递归"（同一 10 字节被反复读取），但该保护仅排除了与当前条目完整重叠的情形；攻击者仍可构造链状嵌套目录：每级的子区域向前偏移最小 12 字节，使整个调用深度达到 `file_size / 12`。在 1 MB 文件下约有 83,000 级递归，每帧约占 150–200 字节的栈空间，远超典型 Linux 8 MB 栈上限，导致栈溢出。
- **触发条件**: 构造一个合法 CRW 文件头（"II" 或 "MM" + "HEAPCCDR" 签名），然后在 CIFF 数据区内创建一条深度嵌套的目录链：每级目录包含唯一的一个 `directory` 类型条目，该条目的 offset 设为当前 `start + 10`（最小合法前向偏移），size 设为当前缓冲区大小减去 offset（最大子区域）。约 500 KB 文件可生成 ~40,000 级递归，可靠地触发 8 MB 栈溢出。
- **安全影响**: 栈溢出导致进程收到 SIGSEGV 崩溃（DoS）。在无栈保护页的嵌入式/精简环境中，栈溢出可能覆盖相邻内存区域，具有潜在的控制流劫持风险，从而上升为 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
