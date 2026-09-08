Analyzing all key paths now.

**Dimension computation (lines 62–63):** `w = (buf[0]+1)*8`, `h = (buf[1]+1)*8`. `buf[0]` is `uint8_t` [0,255], so w,h ∈ [8,2048]. No overflow possible.

**Allocation (lines 77–78):** `av_mallocz(avctx->width * avctx->height * 2)`. Max = 2048×2048×2 = 8,388,608 — well within `int` range, no overflow.

**`memcpy` from previous frame (lines 119–130):**
- `start = (outcnt + offsets[oidx]) % maxcnt` — result ∈ [0, maxcnt−1].
- `count = (code & 0x3FF) + 3` — max 1026.
- Guard: `if (maxcnt - start < count || maxcnt - outcnt < count) break;` — ensures both source and destination stay within `[0, maxcnt)`. All offsets are multiplied by 2 in `memcpy`, but the bounds math is done in pixel units then scaled. No overflow.

**`av_memcpy_backptr` (lines 145–148):**
- `offset = (code & 0x1FFF)+1` — max 8193. `count` max 259.
- Guard: `if (outcnt < offset || maxcnt - outcnt < count) break;` — ensures source start `≥ 0` and destination end `≤ maxcnt`. Safe.

**Buffer read bounds:** Every read of 2 bytes, 3 bytes, or 1 byte is guarded by `buf_end - N >= buf` checks before the read.

**`offsets[oidx]`:** `AV_RL24` returns [0, 16777215] stored as `int` — no sign issue; modulo by `maxcnt > 0` keeps result in-bounds.

No exploitable memory-safety vulnerability found in any of these paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
