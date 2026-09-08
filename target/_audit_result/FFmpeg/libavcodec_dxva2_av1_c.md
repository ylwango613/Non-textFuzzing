Based on my thorough analysis of `dxva2_av1.c` and all related structures (`av1dec.h`, `cbs_av1.h`, `cbs_av1_syntax_template.c`, `av1.h`, `mem.c`), here is my complete audit:

**Analysis summary:**

- Film grain loops: CBS enforces `num_y_points ≤ 14`, `num_cb_points ≤ 10`, `num_cr_points ≤ 10`; ar_coeffs arrays are 24/25 exactly matching hardcoded loop bounds. Safe.
- Tile array `ctx_pic->tiles[tile_num]`: tile_count is checked `≤ MAX_TILES=256`, CBS enforces `tg_end ≤ num_tiles−1`, so `tile_num ≤ 255`. Safe.
- `ref_frame_idx` as array index: CBS bounds values to [0,7] (3-bit read); `h->ref[AV1_NUM_REF_FRAMES=8]`. Safe.
- `remap_lr_type[lr_type[i]]`: `lr_type` is 2-bit (CBS `fbs(2,...)`), values 0-3, array size 4. Safe.
- `gm_params[AV1_REF_FRAME_LAST + i]`: `AV1_REF_FRAME_LAST=1`, `i∈[0,6]` → indices 1-7, within `[0, AV1_NUM_REF_FRAMES−1=7]`. Safe.
- `loop_filter_ref_deltas[0..7]`: array size is `AV1_TOTAL_REFS_PER_FRAME=8`. Safe.
- **Integer overflow at line 330**: `ctx_pic->bitstream_size + size` where both are 32-bit unsigned; if overflow wraps to a value ≤ `bitstream_allocated`, `av_fast_realloc` returns existing (undersized) buffer and the subsequent `memcpy` at line 336 writes `size` bytes at offset `bitstream_size`, past the allocated region. However, triggering this requires the accumulated OBU data to exceed 4 GB, which is impractical.

## VULN: Integer overflow in DXVA2 AV1 bitstream size accumulation leads to heap OOB write
- **漏洞类别**: memory-safety
- **函数**: dxva2_av1_decode_slice()
- **行号**: 329-336
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 4.2 (AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Low
- **攻击向量**: crafted media file (AV1 bitstream with tile group OBUs)
- **外部触发路径**: `ffmpeg -i <crafted_av1.mp4> -hwaccel dxva2 -f null -` → `avcodec_send_packet()` → `av1dec_decode()` → `dxva2_av1_decode_slice()` → `av_fast_realloc(ctx->bitstream_cache, &ctx->bitstream_allocated, ctx_pic->bitstream_size + size)` → `memcpy(ctx_pic->bitstream + ctx_pic->bitstream_size, buffer, size)`
- **描述**: 在 `dxva2_av1_decode_slice()` 的非快捷路径（多个 tile group 分批送入时），第 330 行计算 `ctx_pic->bitstream_size + size` 时，两个操作数均为 32-bit 无符号整数（`unsigned` + `uint32_t`），相加结果若超过 `2^32` 则发生无符号回绕，得到的小值传给 `av_fast_realloc` 作为 `min_size`（`size_t` 参数）。由于 `av_fast_realloc` 在 `min_size ≤ *size` 时直接返回现有指针（不重新分配、不修改大小），后续第 336 行的 `memcpy(ctx_pic->bitstream + ctx_pic->bitstream_size, buffer, size)` 将在实际分配容量之外写入 `size` 字节，造成堆越界写。
- **触发条件**: 攻击者需构造一个包含多个 tile group OBU 的 AV1 流，使得所有 tile group OBU 的累积数据量（即多次调用 `decode_slice` 的 `size` 之和）超过 4 GB（触发 32-bit 无符号溢出）。目标系统需安装支持 DXVA2 或 D3D11VA 的 Windows GPU 硬件加速驱动并通过 `-hwaccel dxva2` 或 `-hwaccel d3d11va` 启用。
- **安全影响**: 最坏情况下堆内存越界写，可能导致远程代码执行（RCE）；更可能的结果是进程崩溃（DoS）。受制于需要 >4 GB 的 tile group 数据，实际可利用性极低。

<!-- AUDIT_PROMPT_VERSION: 1 -->
