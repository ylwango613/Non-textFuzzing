After fully reading the 331-line encoder and tracing all relevant code paths:

- **scratch buffer** (`av_malloc_array(avctx->width + 1, ...)`, line 278): The `+1` is intentional — `ljpeg_encode_bgr` accesses `buffer[x+1][i]` (line 104) where `x < width`, so max index is `buffer[width][i]`, which is always in bounds. **Safe.**
- **max_pkt_size arithmetic** (lines 222–227): `width * height * 3 * 4` is signed-int multiplication that could overflow with extreme dimensions, but FFmpeg validates `avctx->width/height` in `avcodec_open2` before reaching this point; values large enough to overflow would be rejected earlier.
- **hsample/vsample**: Fixed to {1,2} by `ff_mjpeg_init_hvsample`; no overflow risk in MB calculations.
- This is an **encoder** (`ff_ljpeg_encoder`), not a decoder. It is not in the attack surface of parsing crafted media files with `ffmpeg -i <file> -f null -`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
