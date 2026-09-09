After exhaustive multi-pass analysis of all seven decode functions in `qtrle.c`, I verified the following:

**Batch 1 (lines 1–200):** `qtrle_decode_1bpp` and `qtrle_decode_2n4bpp` — rle_code derives from `int8_t` cast (max magnitude 128), all multiplications in CHECK_PIXEL_PTR arguments stay well within int range (max ~2048). Skip arithmetic via `bytestream2_get_byte() - 1` can produce a large unsigned that wraps to a negative `pixel_ptr` on int assignment, and `CHECK_PIXEL_PTR(0)` correctly catches the negative result.

**Batch 2 (lines 200–354):** `qtrle_decode_8bpp`, `qtrle_decode_16bpp`, `qtrle_decode_24bpp` — `bytestream2_get_buffer` at line 245 writes exactly `rle_code` bytes, pre-validated by `CHECK_PIXEL_PTR(rle_code)`. The vectorized 24bpp path uses `AV_WN32` + `AV_WN16` for two pixels at once; total bytes per pair is 6 = 2×3, and the pre-check `CHECK_PIXEL_PTR(rle_code * 3)` mathematically covers the full range of all loop writes.

**Batch 3 (lines 355–593):** `qtrle_decode_32bpp` and the frame dispatch — `AV_WN64` writes 8 bytes per pair (2×4), pre-checked by `CHECK_PIXEL_PTR(rle_code * 4)`. Frame dimensions validated at lines 485–488 before calling any decode function.

**pixel_limit integer overflow analysis:** `pixel_limit = linesize[0] * height` computed as `int`. For frames large enough to overflow int32, the result wraps modularly to a value ≤ the actual buffer size (since the real product exceeds 2^31, the int32 result is either negative or smaller), making CHECK_PIXEL_PTR only stricter — it cannot produce a bound that exceeds the real allocated buffer size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
