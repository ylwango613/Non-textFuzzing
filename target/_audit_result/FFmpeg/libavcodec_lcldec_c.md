I've now completed a full read of the file in three passes (lines 1–600, 600–685), reviewed `lcl.h` for all constants and flags, checked `libavutil/imgutils.c` for `av_image_check_size2` limits, and verified the `avcodec.c` dimension-check call. Here is the final analysis by vulnerability pattern:

**Group 1 — `decode_init()` integer overflow (lines 504–558)**

`basesize = avctx->width * avctx->height` and `max_basesize = FFALIGN(w,4)*FFALIGN(h,4)` are computed as signed `int*int`. However, `avcodec_open2()` calls `av_image_check_size2()` (avcodec.c:242–243) before `decode_init()` is invoked. The check rejects any image where `8w*(h+128) ≥ INT_MAX`, capping safe dimensions at roughly 16 383×16 383 — well below the overflow threshold. This path is guarded.

**Group 2 — ZLIB multithread path missing `len < 8` check (lines 285–296)**

The MSZH multithread path (lines 204–206) explicitly checks `len < 8 || len - 8 < mthread_inlen` and returns `AVERROR_INVALIDDATA`. The ZLIB path (lines 285–296) uses only:
```c
mthread_inlen = FFMIN(mthread_inlen, len - 8);
```
When `len < 8`, `len - 8` underflows to ~`UINT_MAX`, making the FFMIN ineffective and `mthread_inlen` potentially up to `0xFFFFFFFF`. However, `zlib_decomp()` then passes this `src_len` to zlib's `inflate()` with `next_in = buf + 8` (which points into the zero-filled AV_INPUT_BUFFER_PADDING_SIZE region). Zlib validates the CMF/FLG header bytes immediately — `0x00` bytes are not a valid deflate stream (CM must be 8) — so `inflate()` returns `Z_DATA_ERROR` after reading at most 2 bytes, `zlib_decomp` returns `AVERROR_UNKNOWN`, and `decode_frame` propagates the error before reaching the second `zlib_decomp` call or the `memset`. No heap OOB write or read actually occurs.

**Group 3 — `mszh_decomp` one-byte read before loop (lines 85–86)**

Reading `mask = *srcptr++` before the `while` guard can read 1 byte past the caller-supplied data length. The function's documented contract ("srcptr must be padded with at least 5 extra bytes") is satisfied at all three call sites because AVPacket data always carries `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) of zeroed padding beyond `avpkt->size`.

**Group 4 — PNG filter and colorspace conversion OOB analysis**

All colorspace conversion loops read at most `c->decomp_size` bytes from `c->decomp_buf`, which is allocated at size `max_decomp_size ≥ c->decomp_size`. Partial decompression is handled by a `memset` to zero in `zlib_decomp` before returning, so no uninitialized or out-of-bounds bytes are read.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
