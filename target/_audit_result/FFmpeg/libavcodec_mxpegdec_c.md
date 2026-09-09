After fully reading `mxpegdec.c` (368 lines) and examining the related `mjpegdec.h`/`mjpegdec.c` calling context, here is my complete analysis of all suspicious code paths:

**Group 1 (lines 94-145): `mxpeg_decode_mxm`**
- `mb_count = s->mb_width * s->mb_height` — both `unsigned`, both from `AV_RL16` (max 65535 each). Max product = 65535 × 65535 = 4,294,836,225 < UINT32_MAX. No overflow.
- `bitmask_size = (mb_count + 7) >> 3` — max `mb_count + 7 = 4,294,836,232 < UINT32_MAX`. No overflow.
- Bounds check `bitmask_size > buf_size - 12`: `buf_size` is always ≥ 13 from the COM path (`len > 14` → `len-2 ≥ 13`), so `buf_size - 12 ≥ 1 > 0`. The signed-to-unsigned promotion cannot produce a false negative here.
- `memcpy(s->mxm_bitmask, buf_ptr + 12, bitmask_size)` is strictly bounded by the above check.

**Group 2 (lines 147-160): `mxpeg_decode_com`**
- `strncmp(buf_ptr + 2, "MXM", 3)` — requires ≥ 5 bytes; `len > 14 && len <= buf_size` guarantees `buf_size ≥ 15`. Safe.

**Group 3 (lines 193-353): `mxpeg_decode_frame`**
- `picture_index ^= 1` — always 0 or 1, within `picture[2]` bounds. Safe.
- `jpg->mb_bitmask_size = s->bitmask_size` passed to `ff_mjpeg_decode_sos` — the size-mismatch check at `mjpegdec.c:1452` gates further use. Safe.

**Group 4: `mjpegdec.c:1452`**
- `(s->mb_width * s->mb_height + 7) >> 3` — MJpeg `mb_width`/`mb_height` are `int`, bounded to ≤ 4096 by SOF dimension limits. Max product = 16,777,216. No overflow.

No externally-triggerable memory safety bugs found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
