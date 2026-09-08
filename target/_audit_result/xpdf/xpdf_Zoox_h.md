I have now read the entire `Zoox.h` (269 lines) and `Zoox.cc` (1077 lines) in full, and traced the call chain from PDF-embedded XMP/XFA data into `ZxDoc::loadMem`. Below is my analysis of each suspicious region:

**Group 1 — parseDocTypeDecl state machine (lines 356–398):** `quote` is initialized to `'\0'` and never assigned to the actual quote character encountered in state 0, so state 1/3 can never exit normally. This is a logic bug causing the parser to consume all remaining input, but it does not corrupt memory.

**Group 2 — hex/decimal numeric character references (lines 453–487, 571–604):** `x` is `unsigned int`; the shift/multiply accumulation wraps modulo 2^32 on overflow (defined UB-free for unsigned). All paths call `appendUTF8(value, x)` which appends at most 6 bytes to a `GString` (dynamically managed). No memory corruption.

**Group 3 — appendUTF8 for c > 0x7FFFFFFF (lines 641–670):** Values above 0x7FFFFFFF cause no branch to execute — they are silently dropped. Not a memory safety issue.

**Group 4 — `start - 1` pointer in unknown entity fallback (lines 510, 627):** `start - 1` points to the `&` character that was consumed with `++parsePtr` before `start = parsePtr`. Since `parsePtr` was a valid buffer position when `&` was read, `start - 1 >= data`. Pointer is in-bounds.

**Group 5 — parseCDSect/parseComment/parsePI loop bounds (lines 678, 715, 735):** Loop conditions ensure at least 3 (or 2) bytes remain before `strncmp` reads them. No out-of-bounds read.

**Group 6 — loadFile size truncation (lines 225–228):** `ftell` result cast to `Guint` (32-bit unsigned) could truncate for files >4 GB, but `fread` is called with the same truncated `dataLen`. For practical PDF XMP/XFA payloads this is not reachable.

**Group 7 — GString::append with potentially large n (line 510):** For a 2GB+ entity name, `(int)(parsePtr - start) + 1` could signed-overflow to negative. GString::append with a negative length could misbehave, but this requires a >2GB document, making it impractical via embedded XMP/XFA.

After full analysis, no practically exploitable memory safety vulnerabilities (heap overflow, OOB write, UAF, OOB read) are present in Zoox.h / Zoox.cc.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
