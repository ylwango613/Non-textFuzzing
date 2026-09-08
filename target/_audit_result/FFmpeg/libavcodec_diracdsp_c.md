**Analysis summary of `diracdsp.c`:**

After thorough review, I examined every function and macro:

1. **`DIRAC_WEIGHT` loop (lines 96-99, 108-111)**: The loop uses `x++` instead of `x+=2`, causing `block[W]` / `dst[W]` to be written when `x=W-1`. However, `mcscratch` is allocated in `alloc_buffers()` as `av_malloc_array(stride + 64, MAX_BLOCKSIZE)` — the explicit `stride += 64` (line 331 of diracdec.c) means the single extra write is always within the allocated buffer. Not a heap OOB.

2. **`dirac_hpel_filter` negative-index writes (line 38-39)**: Writes to `dstv[-3...-1]`. The hpel buffers have `+16` bytes of prefix padding (`ref->hpel[plane][i] = ref->hpel_base[plane][i] + edge*linesize + 16`), so all three negative indices land inside the allocated prefix. Not OOB.

3. **`FILTER` macro vertical reads at negative stride offsets**: Reads up to `src[-3*stride]`. Caller ensures `EDGE_WIDTH/2 = 8` rows of `draw_edges` padding above/below the source plane; 3 < 8. Safe.

4. **`put_signed_rect_clamped_8bit_c` / `PUT_SIGNED_RECT_CLAMPED` non-mod-4 width (lines 148-153, 169-172)**: With width not divisible by 4, the last loop iteration accesses `dst/src[x+3]` past the valid width. However, the idwt buffer row stride is `FFALIGN(idwt.width, 8) * sizeof`, which provides alignment padding beyond `p->width`; likewise the frame stride (linesize) has alignment padding. All accesses remain within allocated bounds.

5. **`ADD_OBMC` fixed 32-byte row advance (line 133)**: `obmc_weight += 32` regardless of `xblen`. The obmc_weight array is `s->obmc_weight[3][MAX_BLOCKSIZE * MAX_BLOCKSIZE]` with `MAX_BLOCKSIZE=32`, so each row is exactly 32 bytes. Correct.

6. **`DEQUANT_SUBBAND` stride computation (line 212)**: `tot_h << (sizeof(PX) >> 1)` correctly produces `tot_h * sizeof(PX)` bytes. No overflow risk since subband dimensions are bounded by the validated video dimensions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
