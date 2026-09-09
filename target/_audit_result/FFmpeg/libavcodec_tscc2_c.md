I have now read the entire `tscc2.c` file and examined all relevant supporting structures. Here is my complete analysis before the final verdict:

**Potential concern 1 — `av_malloc(c->mb_width * c->mb_height)` (line 345)**
Signed-int multiplication with no overflow check. However:
- If the product overflows to a negative `int`, the cast to `size_t` produces a value > INT_MAX; `av_malloc` returns NULL; the NULL-check at line 346 catches it.
- If the product overflows to a small positive value (requires mb_width ≈ mb_height ≈ 65536, i.e., width ≈ 1 M pixels, height ≈ 524 K pixels), the resulting frame size ≈ 1.6 TB is rejected by `ff_reget_buffer` at line 234 long before any slice decode loop is entered.
- Mathematical exclusion: for any frame that `ff_reget_buffer` can allocate (width × height × 3 < INT_MAX ≈ 2.1 GB → width × height < 715 M), the true mb product ≤ 715 M / 128 ≈ 5.5 M < 2^31, so the signed-int multiplication cannot overflow.

**Potential concern 2 — `off = mb_x * 16 + mb_y * 8 * c->pic->linesize[i]` (line 198)**
For large mb_y and large linesize this could overflow `int`. The overflow condition is mb_y × 8 × linesize > INT_MAX, i.e., (height/8) × 8 × width > INT_MAX, i.e., width × height > 2.1 B. But that frame cannot be allocated (same INT_MAX bound). Mutually exclusive with frame allocation success.

**Potential concern 3 — `c->slice_quants[mb_x + c->mb_width * mb_y]` (line 193)**
OOB read would only occur if `slice_quants` was under-allocated (requires the same unreachable overflow scenario). Clean in practice.

**`ff_zigzag_scan[bpos]` (line 174)**
`bpos` is checked `< 16` before use; `ff_zigzag_scan` is declared `uint8_t[16+1]` with values 0–15; `c->block[16]` indexed safely.

**VLC-set index `c->quant[q-1] - 2` (line 199)**
`c->quant[q-1]` is validated to [2, NUM_VLC_SETS+1] = [2, 14], so vlc_set ∈ [0, 12], within the 13-entry arrays. Safe.

**Bytestream reads (lines 259-287)**
All `size` values are checked against `bytestream2_get_bytes_left`; reads-past-end in `bytestream2` return 0 bytes padded. The loop-write bounds check `pos + len > num_mb` uses the same overflowed `num_mb` as the allocation, keeping writes inside the allocated buffer. No OOB.

All theoretical integer-overflow paths are gated by `ff_reget_buffer` failing for the same extreme dimensions that would be required. No independently exploitable memory-safety bug exists.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
