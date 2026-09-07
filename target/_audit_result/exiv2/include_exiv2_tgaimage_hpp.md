I've now fully audited both `tgaimage.hpp` and `tgaimage.cpp`, and traced the supporting types. Here is my analysis:

**`readMetadata()`** (lines 44–87):
- `buf[18]` is stack-allocated; `read()` return value is checked against `sizeof(buf)` before accessing any byte — no OOB.
- `getShort(buf + 12, …)` and `getShort(buf + 14, …)` access bytes 12–13 and 14–15 of an 18-byte buffer — both within bounds.
- Results are stored into `uint32_t pixelWidth_`/`pixelHeight_` — no integer overflow on assignment.

**`isTgaType()`** (lines 104–127):
- `buf[26]` is stack-allocated; `memcmp(buf + 8, …, 16)` accesses bytes 8–23 of a 26-byte buffer — within bounds.
- `iIo.read(buf, 26)` return value is unchecked (partial-read leaves stack bytes uninitialized for `memcmp`), but this is purely a logic/mis-classification issue — the comparison result stays within bounds and there is no heap allocation driven by it.
- The `curPos < 26` guard uses current-file-position instead of file-size (logic error), but the worst outcome is a wrong boolean return value — no memory corruption path.

The entire TGA handler is intentionally described as "just a stub — we only read width and height." It performs no dynamic allocation, no recursive traversal, no IFD parsing, and no memcpy driven by attacker-controlled lengths. Every buffer access is either statically bounded or guarded by a read-length check.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
