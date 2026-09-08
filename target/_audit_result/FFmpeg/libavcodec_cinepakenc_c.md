No upper-bound check exists on `avctx->width/height`. Now I have enough context to write the final report.

**Summary of findings from all three read batches:**

- Lines 181 and 188: `(6 * (avctx->width * avctx->height)) >> 2` computed in signed int before being passed to `av_malloc_array`/`av_malloc`. With w=4, h=178956972 (both multiples of 4, passing the `& 3` check): `6 * 715827888 = 4294967328` overflows signed int32 → wraps to 32 → `32 >> 2 = 8`. Result: `av_malloc_array(8, 4)` = 32 bytes and `av_malloc(32)` = 32 bytes for each `pict_buf[]`. Actual required storage is ~1 GB per buffer. The encoder then writes far beyond each 32-byte boundary during `rd_frame`→`quantize`.
- `temp[64]` in `encode_mode`: correctly sized (max 16 V4 blocks × 4 bytes = 64 bytes per 32-bit window), no overflow.
- No other reachable OOB patterns found.

---

## VULN: Integer Overflow → Heap Underalloc in cinepak_encode_init (RGB24, pict_bufs + codebook_input)
- **漏洞类别**: memory-safety
- **函数**: cinepak_encode_init()
- **行号**: 181-188
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i malicious.avi -c:v cinepak output.avi → avcodec_open2() → cinepak_encode_init() → av_malloc_array((6 * (w*h)) >> 2, sizeof(int)) [line 181] and av_malloc((6 * (w*h)) >> 2) [line 188] → heap underalloc → cinepak_encode_frame() → rd_frame() → rd_strip() → quantize() / encode_mode() → OOB heap write
- **描述**: `cinepak_encode_init` computes allocation sizes for `codebook_input` (line 181) and each `pict_bufs[x]` (line 188) using the signed-int expression `(6 * (avctx->width * avctx->height)) >> 2`. With dimensions such as width=4, height=178956972 (both multiples of 4, satisfying the only check at line 159), the intermediate `6 * (4 * 178956972) = 6 * 715827888 = 4294967328` overflows signed int32 (wraps to 32 under two's complement), and `32 >> 2 = 8`. Consequently `av_malloc_array(8, sizeof(int))` allocates only 32 bytes for `codebook_input` and `av_malloc(32)` allocates 32 bytes per `pict_buf`. The actual memory required is `(6 * 715827888 / 4) * sizeof(int) ≈ 4 GB` for `codebook_input` and ≈ 1 GB per `pict_buf`. The overflow in the argument expression precedes entry into `av_malloc_array`'s own `size_mult` guard, so that guard is bypassed entirely. On the first encoding call, `quantize()` iterates over all 44,739,243 macroblocks writing into `s->codebook_input`, and `get_sub_picture` / `copy_mb` / `decode_v*_vector` write into `pict_bufs`, both causing massive out-of-bounds heap writes within the first few rows of the frame.
- **触发条件**: 攻击者构造一个 AVI（或 MOV）输入文件，将视频流的宽度设置为 4、高度设置为 178956972（或任意满足 `6 * (w * h) mod 2^32` 为小正数且 w,h 均为 4 的倍数的尺寸对），然后诱导用户以 cinepak 编码器进行转码（例如 `ffmpeg -i malicious.avi -c:v cinepak out.avi`）。视频处理管线或在线转码服务若默认对 AVI 容器使用 cinepak 编码器，则可在无额外用户干预的情况下触发。
- **安全影响**: 堆越界写入，可覆盖后续堆分配的元数据或对象指针，在攻击者精心构造的维度下最坏情况可导致任意代码执行（RCE）；即使利用不成功也会导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
