I've now completed a thorough multi-pass analysis of `dirac_dwt_template.c` together with its header (`dirac_dwt.h`), the companion implementation (`dirac_dwt.c`), and the allocation site in `diracdec.c`. Below is the security assessment of each potential concern found:

**`tmp[-1]` / `tmp[w2+1]` writes** (lines 94-95, 117-118):  
These are intentional. `spatial_idwt_init` shifts `d->temp` forward by 8 elements (`((TYPE *)d->temp) + 8`). The temp buffer is allocated as `(w+16) * sizeof(TYPE)` bytes, giving 8 elements of headroom before the shifted pointer. All negative-index writes land within the allocation.

**`b[w2+2]` reads in `horizontal_compose_dd137i` for small widths (w=4)** (line 111):  
Row buffers have stride-based padding beyond the logical subband width. Reading one or two elements past the logical end of a row at a given DWT level falls into padding within the contiguous `buf_base` allocation. Not exploitable.

**`b[-1]` read in `horizontal_compose_dd137i` for w=2** (line 114):  
Row pointers use `av_clip(y, 0, height-2)`, so the minimum row is 0 (i.e., `buffer`). `buffer = buf_base + (top_padding * w_padded) * sizeof_element` where `top_padding = FFMAX(1<<MAX_DWT_LEVELS, max_yblen/2) ≥ 256`. Reading `b[-1]` from the first row falls 256+ rows into the allocation — well within `buf_base`.

**`spatial_compose_haari_dy` at height-1 levels** (line 416):  
At level n, `stride_l = d->stride << n`. Accessing `b1 = buffer + 1 * stride_l` for hl=1 reads the adjacent stride block, which is still within the padded allocation (`top_padding + CALC_PADDING + max_yblen/2` rows).

**All `b[]` writes** in horizontal compose inner loops:  
Maximum write index is `b[2*(w2-1)+1] = b[w-1]`. Always within bounds.

**Allocation overflow protection**:  
`av_calloc` and `av_malloc_array` both perform internal multiplication-overflow checks before allocating. The `pshift`-based size expressions are bounded by codec limits.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
