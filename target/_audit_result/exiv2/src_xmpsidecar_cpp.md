Now I have enough context to complete the analysis. Let me verify the `isXmpType` buffer math and the XMLValidator recursion guard.

**Group 1 — `isXmpType()` (lines 162–203):**
- `buf[80]` stack array, two reads: `iIo.read(buf, xmlHdrCnt+1)` = 55 bytes into `buf[0..54]`, then `iIo.read(buf + 55, 25)` into `buf[55..79]`. Total = 80 ≤ 80. No OOB.
- The `iIo.seek(-(len - start), BasicIo::cur)` at line 200 correctly seeks back the number of bytes consumed (accounting for BOM). No underseek/overseek exploitable condition.
- `buf[80]` is uninitialized; if the file is 0 bytes, `strncmp` reads up to 54 bytes of stack garbage, but returns non-zero (garbage ≠ xmlHeader), causing `isXmpType` to return false. No data leaks, no memory corruption.

**Group 2 — `readMetadata()` (lines 46–88):**
- File read loop uses a `unique_ptr<byte[]>(65536)` heap buffer, appends to `std::string xmpPacket` in chunks. All sizes are bounded by actual IO read return values. No OOB.
- Recursion depth: `DecodeParams dp(max_recursion_depth_)` is passed to `XmpParser::decode` → `XMLValidator::check`. Inside `XMLValidator::startElement`, the depth check fires at `element_depth_ > max_recursion_depth_` and records the error, which is thrown **before** `SXMPMeta meta(...)` at line 690. The xmpsdk is never called with a too-deeply-nested document. No stack overflow reachable.

**Group 3 — `writeMetadata()` (lines 94–150):**
- `xmpPacket_ = xmlHeader + xmpPacket_ + xmlFooter` is pure `std::string` concatenation. Safe.
- `tempIo.write(xmpPacket_.data(), xmpPacket_.size())` — size is self-consistent. No OOB.

**Group 4 — convert functions (lines 86–87 call into convert.cpp):**
- `copyXmpToIptc`/`copyXmpToExif` delegate to the `Converter` class in convert.cpp, outside the audit scope of this file.

**Conclusion:** No exploitable memory-safety bugs are present in `xmpsidecar.cpp`. The recursion-depth guard in `XMLValidator` correctly pre-validates XML depth before invoking the xmpsdk, all buffer reads are size-bounded, and string operations use RAII containers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
