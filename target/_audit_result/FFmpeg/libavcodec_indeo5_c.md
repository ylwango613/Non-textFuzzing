After thoroughly reading all 699 lines of indeo5.c in two batches and examining the shared ivi.c (1229 lines), I have completed the following analysis:

**Batch 1 (lines 0–586):** decode_gop_header, decode_pic_hdr, decode_band_hdr, decode_mb_info — checked all array accesses, dimension reads, motion-vector bounds checks.

**Batch 2 (lines 587–699):** switch_buffers, decode_init — trivial, no allocations.

**ivi.c deep-read:** ff_ivi_init_planes, ff_ivi_init_tiles, ivi_decode_coded_blocks, ivi_decode_blocks, ivi_process_empty_tile, prepare_buf, ff_ivi_decode_frame — all allocation sites and transform callers.

Key findings per potential pattern:

1. **ivi5_common_pic_sizes OOB**: pic_size_indx is 4-bit, IVI5_PIC_SIZE_ESC=15 handled separately; remaining range 0–14 gives max index 29 in a 30-element array — safe.

2. **buf_size overflow in ff_ivi_init_planes**: `width_aligned * height_aligned * sizeof(int16_t)` is uint32_t; max (8192×8192×2 = 134 MB) well within uint32_t — safe. av_image_check_size2 guards dimension validity first.

3. **av_mallocz(2 * band->bufsize)**: bufsize is int, max ~67M; 2×67M = 134M << INT_MAX — safe.

4. **band->corr array**: declared `uint8_t corr[61*2]`; num_corr validated ≤ 61 before loop `i < num_corr*2`; max index 121 within bounds — safe.

5. **rvmap_sel OOB**: get_bits(3) = 0–7, or constant 8; array rvmap_tabs[9] covers indices 0–8 — safe.

6. **Motion-vector bounds check**: mv fields are int8_t (−128 to 127); arithmetic with max pic dimensions (13-bit, max 8191) stays within int32 range; upper-bound check compares int against int (band->bufsize - 1) correctly — safe.

7. **scan_pos OOB in ivi_decode_coded_blocks**: `scan_pos >= num_coeffs` exit condition guards band->scan[] access; VLC error (-1) caught by `sym >= 256U` check — safe.

8. **transform write OOB**: min_size vs buf_size check at each ivi_decode_coded_blocks / ivi_decode_blocks call site prevents OOB writes into band->buf — safe.

9. **FFSWAP(int16_t, valtab[idx], valtab[idx])**: valtab is int8_t; the FFSWAP macro operates on the lvalue's declared type (int8_t), so no read of a second adjacent byte occurs — safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
