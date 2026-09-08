**Analysis summary — MD5.cpp (236 lines):**

**`MD5_CTX` layout** (MD5.h):
- `buf[4]` = 16 bytes, `bytes[2]` = 8 bytes, `in[16]` = 64 bytes — all fixed-size stack fields.

**`byteSwap`** (lines 30-42): called only as `byteSwap(ctx->in, 16)`, `byteSwap(ctx->in, 14)`, `byteSwap(ctx->buf, 4)` — all counts exactly match the fixed array sizes. No OOB.

**`MD5Update`** (lines 64-98):
- Line 75: `t = 64 - (t & 0x3f)` → t ∈ [1, 64] (space available in ctx->in)
- Line 76-77 (`t > len` branch): writes `len` bytes at offset `64-t`; total bytes = `64-t+len < 64`. Stays within 64-byte ctx->in.
- Line 81: writes exactly `t` bytes at offset `64-t`; total = 64. Exact fit.
- Line 89: `memcpy(ctx->in, buf, 64)` — always 64 into 64. OK.
- Line 97: `memcpy(ctx->in, buf, len)` — `len < 64` at this point. OK.

**`MD5Final`** (lines 104-134):
- `count = ctx->bytes[0] & 0x3f` → range 0..63.
- `*p++ = 0x80` at byte `count` (0..63) — always valid.
- `count = 56 - 1 - count` = `55 - old_count`
- When `count < 0` (old_count = 56..63): `memset(p, 0, count+8)` where `count+8` = 0..7; p = ctx->in + old_count + 1; the zero-fill ends at byte 63 at most. No OOB.
- When `count >= 0` (old_count = 0..55): `memset(p, 0, count)` zeroes bytes `old_count+1`..55. Fits in ctx->in.
- Length append at `ctx->in[14]` and `ctx->in[15]` — DWORDs 14 and 15 are within the 16-element array.
- `memcpy(digest, ctx->buf, 16)` — both sides are 16 bytes. OK.

**Call site** (XMPUtils.cpp:1844-1846): MD5 is called on `tempStr`/`tempLen` which is an internally-serialized XMP buffer, not a raw attacker-controlled byte stream passed directly from a file.

All memory operations are strictly bounded by the algorithm's fixed 64-byte block invariant. No memory safety vulnerabilities exist in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
