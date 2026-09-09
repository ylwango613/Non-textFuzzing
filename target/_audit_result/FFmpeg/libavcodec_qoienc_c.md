Analysis complete. Here is my full audit of `qoienc.c` (with `qoidec.c` and supporting infrastructure examined for context):

**Candidate 1 — `packet_size` integer overflow (line 40)**

```c
packet_size = avctx->width * avctx->height * (channels + 1LL) + 14LL + 8LL;
```

`avctx->width * avctx->height` is an `int × int` multiplication, computed in 32-bit arithmetic before promotion to `int64_t`. At first glance this can overflow. However, `avcodec_open2` calls `av_image_check_size2(avctx->width, avctx->height, max_pixels, AV_PIX_FMT_NONE, ...)` which enforces the stride constraint `(8·w + 1024)·(h + 128) < INT_MAX`. This caps `w·h` to roughly 268 million — well within `INT_MAX` (~2.1 billion). The int32 product therefore cannot overflow.

**Candidate 2 — packet buffer over-write**

The per-pixel worst-case output is `channels + 1` bytes (the RGBA opcode path). The run-flush byte (line 67/118) is amortized within that budget across any pixel sequence. The allocation `w·h·(channels+1) + 22` (14-byte header + 8-byte footer) exactly covers the worst case. No overflow is possible.

**Candidate 3 — `src + x * channels` OOB read (line 55)**

`x * channels` is also `int × int`, but with valid dimensions `x ≤ w − 1 ≤ 2,080,766` and `channels ≤ 4`, the product is at most ~8 million — far from int32 saturation. No overflow.

**Decoder cross-check — `len = width * height * channels` (qoidec.c:70)**

Same integer promotion concern; mitigated by `ff_set_dimensions`/`av_image_check_size2` before the computation, bounding the product to ≤ ~1.07 billion (fits in int32). The unchecked bytestream reads (`get_byteu`, `get_bufferu`) are all protected by the outer `bytestream2_get_bytes_left(&gb) > 4` guard.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
