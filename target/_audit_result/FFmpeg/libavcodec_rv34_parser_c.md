**Analysis of `rv34_parse()` (lines 40–77):**

The file is 84 lines. The only potentially dangerous operation is:

**Line 48 — size check:**
```c
if (buf_size < 13 + *buf * 8) { ... }
```
`*buf` is `uint8_t` (0–255); `*buf * 8` is `int` (max 2040); `13 + *buf * 8` max is 2053 — no integer overflow possible.

**Line 54 — `AV_RB32` read:**
```c
hdr = AV_RB32(buf + 9 + *buf * 8);
```
Reads 4 bytes at offsets `[9+*buf*8 … 12+*buf*8]`. The preceding check guarantees `buf_size >= 13 + *buf * 8`, so the last valid index `buf_size-1 >= 12 + *buf*8`. The access is properly bounded.

**Lines 63–70 — PTS arithmetic:**
`pts` is a 13-bit field (0–8191), `& 0x1FFF` masks the result. `key_dts` is `int64_t`; no overflow of practical concern.

No `malloc`/`av_malloc`, no `memcpy`, no buffer writes, no index arrays — the file contains only read-only parsing logic with a single correct bounds guard.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
