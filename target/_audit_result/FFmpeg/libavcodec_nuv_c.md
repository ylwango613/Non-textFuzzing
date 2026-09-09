Based on the complete analysis of nuv.c (357 lines, all read and analyzed) including tracing into `rtjpeg.c`, `lzo.c`, and `utils.c`:

**Key checks verified:**

1. **`codec_reinit` size guard** (line 110): uses `INT_MAX/8` threshold — this conservatively bounds `height * width * 3/2 ≤ 268,435,379`, which provides enough headroom for downstream `height * linesize` multiplications even after 16-byte alignment padding (YUV420P w_align=16 per `avcodec_align_dimensions2`).

2. **memset size overflow** (lines 261-263): `avctx->height * c->pic->linesize[0]` — with YUV420P alignment locked to 16 bytes, max product is ~1.52 billion for the worst-case dimensions that pass `codec_reinit`'s check; stays within `INT_MAX`.

3. **NULL deref / negative outlen in LZO path** (line 217): `av_lzo1x_decode` checks `*outlen <= 0` on entry and returns immediately without touching `out` — no NULL pointer write even when `c->decomp_size == 0`.

4. **Secondary frame header bounds** (lines 227-240): `RTJPEG_HEADER_SIZE = 12` is verified before accessing `buf[6]`, `buf[8]`, `buf[10]` — all within bounds.

5. **Division by zero** (line 278 `height = buf_size / c->width / 3 * 2`): only reachable when `buf_size < c->width * height * 3/2`; when `c->width == 0` this condition is `buf_size < 0` which is never true.

6. **NUV_BLACK memset sizes**: `c->width * c->height ≤ ~178M` (within `int`); `c->pic` allocation succeeds with matching dimensions before this code is reached.

7. **`get_quant` return value ignored** in `decode_init` (line 325): a logic bug (bad quant tables if extradata too short) but no memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
