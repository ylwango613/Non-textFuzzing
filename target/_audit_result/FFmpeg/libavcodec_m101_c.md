I've now read the complete file (115 lines) and cross-checked the calling context. Here is my structured analysis before the final verdict:

**m101_decode_init (lines 28–45):**  
`extradata_size >= 24` is enforced before any byte is touched — `extradata[8]` and `extradata[12]` accesses are safe.

**stride derivation (line 56):**  
`stride = AV_RL32(extradata + 20)` is a signed `int`. If the high bit is set the value is negative. The guard on line 61 rejects it: `stride < min_stride` where min_stride ≥ 0 for any non-negative width.

**Packet-size guard (line 61):**  
`avpkt->size < stride * (uint64_t)avctx->height` — the uint64_t promotion prevents int overflow. Because `avpkt->size` is `int` (≤ INT_MAX), any `stride * height > INT_MAX` is always rejected. For packets that pass, `src_y * stride` (int × int) satisfies `src_y * stride < height * stride ≤ INT_MAX`, so no signed-overflow UB in the later address computations.

**src_y bounds (lines 76–78):**  
Non-interlaced: `src_y = y ∈ [0, height-1]`. Interlaced branches produce `y/2` or `y/2 + height/2`, both within `[0, height-1]`, even for odd heights.

**10-bit block reads (lines 87–99):**  
`min_stride = (width+15)/16 * 40` ensures each 40-byte block is within one stride. `buf_src[2*x+3]` max index = 31 (x=14, even), `buf_src[32+(x>>1)]` max = 39 (x=15). All within the 40-byte block, which itself lies inside the validated packet.

**Frame write indices:**  
`luma[xd]` with `xd < width`, `cb/cr[xd>>1]` with even xd so `xd>>1 < ceil(width/2)` — stays within the frame buffer allocated by `ff_get_buffer`.

**Integer-overflow on min_stride (line 59):**  
`(width+15)/16 * 40` — with FFmpeg's FF_MAX_DIMENSIONS cap (≤ 32768), this is at most ≈ 81,960, well within int range.

No exploitable memory-safety path was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
