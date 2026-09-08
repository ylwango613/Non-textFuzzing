I now have full context. Let me verify the `av_image_check_size2` constraint: for PAL8 (1 bpp), stride ≈ `8*w + 1024`. The check `stride*(h+128ULL) >= INT_MAX` limits `w*(h+128) < ~268M`, meaning `w*h < 268M` — well within int32 range. This rules out integer overflow at line 317. Similarly, `(w/4)*(h/4) < 16.7M` × `vector_bits ≤ 25` = 418M — also within int32, so the `get_bits_left` check at line 222 does not overflow. All `av_reallocp`/`av_reallocp_array` sizes are safe (max 1,048,560 bytes). The `unpack()` copies use `FFMIN` to cap at `dst_end - dst`, and `av_memcpy_backptr` offset is guarded by `dst - dst_start >= offset`. Frame pixel writes stay within `(y*4+j) < height` and `(x*4+i) < width` bounds. Array accesses in the inter-frame loop (`mv_codebook`, `blocks_raw`, `block_codebook`) are all guarded by explicit comparisons before use.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
