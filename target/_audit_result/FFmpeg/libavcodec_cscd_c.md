Now I have a complete picture. Let me verify the maximum `decomp_size` under the enforced constraints to confirm whether the integer overflow in `decode_init` is truly gated.

The `av_image_check_size2` check (line 301 of imgutils.c) enforces:
- `stride_check = 8*w + 1024` (conservative, pix_fmt=NONE)
- Requires `stride_check * (h + 128) < INT_MAX = 2147483647`
- Approximately: `w * h < 268435455 ≈ 2^28`

Under this constraint, maximum `decomp_size = h * FFALIGN(w * bpp, 4)`:
- bpp ≤ 4 (32bpp), `w*h < 2^28`
- `decomp_size ≤ 4 * w * h < 4 * 2^28 = 2^30 = 1073741824`
- Well within `unsigned int` (max 2^32−1) — **no overflow possible**

Similarly, `c->linelen = w * bpp ≤ 4 * sqrt(2^28) ≈ 65536` — no overflow in `int`.

The `bugdelta` computation: `FFALIGN(w*bpp, 4) * h ≤ (4w+3)*h < 5*2^28 ≈ 1.34 billion` — fits in `int`.

All three potential integer-overflow sites in `decode_init`/`decode_frame` are fully covered by the upstream `av_image_check_size2` guard before `decode_init` is ever called. The LZO output limit (`outlen = c->decomp_size`) and the zlib output limit (`dlen` starting at `c->decomp_size`) correctly bound decompression writes to the allocated buffer. `copy_frame_default`/`add_frame_default` read exactly `height * FFALIGN(linelen, 4) = decomp_size` bytes, which matches the allocation. No other unchecked size arithmetic or fixed-size buffer is present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
