After thorough analysis of `lzf.c` (111 lines) and the complete call chain:

**Literal path (lines 64–78):**
- `s` incremented to 1–32, buffer space checked before `bytestream2_get_buffer` write.
- Allocation guard `s + 64 > *allocated_size - len` correctly uses promoted `int64_t` arithmetic.

**Back-reference path (lines 79–102):**
- `l` = 3–264 (bounded), `off` = 1–8192 (bounded).
- `off > len` guard prevents reading before buffer start in `av_memcpy_backptr`.
- Buffer space checked before `av_memcpy_backptr`; write of `l` bytes into `[p, p+l)` stays within `len + l + 64` allocated region.
- `av_memcpy_backptr` handles overlapping copies (run-length intent) correctly via block-doubling and fill helpers.

**`av_fast_realloc` overflow safety:**
- Clamps `min_size` to `UINT_MAX` / `max_alloc_size`; returns NULL if `new_size > UINT_MAX`, which propagates as `AVERROR(ENOMEM)`.

**`*allocated_size` / `len` type mixing:**
- `unsigned int - int64_t` → `int64_t` via usual arithmetic conversions; negative result correctly triggers realloc.

No externally-triggerable memory-safety vulnerability found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
