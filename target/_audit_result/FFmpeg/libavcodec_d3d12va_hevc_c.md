Based on my thorough analysis of `d3d12va_hevc.c` and the related decode infrastructure (`d3d12va_decode.c`), here is my finding:

**Key observations:**

1. `HEVCDecodePictureContext.bitstream_size` is declared as `unsigned` (32-bit) at line 41.
2. Each call to `d3d12va_hevc_decode_slice()` adds `size` (uint32_t) to this 32-bit accumulator (line 91) with no overflow check.
3. `d3d12va_hevc_end_frame()` widens the already-truncated 32-bit value to `uint64_t` at line 163 — too late to recover from a prior wraparound.
4. `d3d12va_resize_bitstream_buffer()` allocates `bitstream_size * 1.5` bytes (line 215) based on the underestimated size.
5. `update_input_arguments()` then copies real (original large) slice data into the undersized buffer via `memcpy` at line 132.

The 1-byte OOB from the `*(uint32_t*)` write (START_CODE_SIZE=3 vs sizeof(uint32_t)=4) when the last slice has size=0 is **mitigated** by the 1.5× allocation factor in the GPU buffer: the physical allocation always covers the logical `bitstream_size + 1` write.

## VULN: Integer Overflow in 32-bit `bitstream_size` Accumulator Causes Undersized D3D12 Upload Buffer and Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: `d3d12va_hevc_decode_slice()` (accumulation, line 91), `d3d12va_hevc_end_frame()` (underestimated buffer size, lines 163-164), `update_input_arguments()` (OOB memcpy, line 132)
- **行号**: 91, 163-164, 132
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.7 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: `ffmpeg -i <crafted_hevc_file> -hwaccel d3d12va -f null -` → `avformat_open_input()` → HEVC packet demux → `ff_hevc_decode_frame()` → `hevcdec.c:3054 FF_HW_CALL(decode_slice, nal->raw_data, nal->raw_size)` → `d3d12va_hevc_decode_slice()` [unsigned bitstream_size wraps at line 91] → `d3d12va_hevc_end_frame()` [widened-but-already-wrapped value used at line 163] → `ff_d3d12va_common_end_frame()` → `d3d12va_resize_bitstream_buffer()` [buffer undersized] → `update_input_arguments()` → `memcpy()` OOB write at line 132
- **描述**: `HEVCDecodePictureContext.bitstream_size` is declared as `unsigned` (32-bit) at line 41. In `d3d12va_hevc_decode_slice()`, each invocation accumulates the per-slice NAL data size into this 32-bit field without overflow protection (`ctx_pic->bitstream_size += size`, line 91). With `MAX_SLICES=256` and no per-slice size cap, the sum can exceed UINT32_MAX (~4 GB) and silently wrap to a small residual value. In `d3d12va_hevc_end_frame()`, the computation `bitstream_size = ctx_pic->bitstream_size + (uint64_t)ctx_pic->slice_count * START_CODE_SIZE` (line 163) widens the already-truncated 32-bit value to 64 bits—it correctly prevents further overflow in this expression, but starts from a wrong base. The D3D12 GPU upload buffer is then allocated at `bitstream_size * 1.5` bytes (an amount far smaller than required). When `update_input_arguments()` iterates over slices and calls `memcpy(mapped_ptr, &ctx_pic->bitstream[position], size)` (line 132) with each slice's original large size, it writes far beyond the allocated buffer boundary into adjacent CPU-mapped GPU memory.
- **触发条件**: 攻击者需构造一个 HEVC 编码视频文件（如 .mp4 或 .mkv 封装），其中单帧包含大量分片（slice），各分片原始 NAL 数据之和超过 2^32 字节（约 4 GB）。例如：256 个分片，每个分片 NAL 数据约 17 MB，总计约 4.35 GB，即可触发 `unsigned bitstream_size` 的 32 位整数溢出。
- **安全影响**: 最坏情况下，攻击者控制溢出后写入 D3D12 CPU 映射 GPU 上传缓冲区（`D3D12_HEAP_TYPE_UPLOAD`）之外的连续内存区域，可能覆盖相邻 D3D12 资源元数据或堆管理结构，在 Windows 平台上可能导致远程代码执行（RCE）。受大文件（>4 GB）触发条件限制，实际利用难度偏高。

<!-- AUDIT_PROMPT_VERSION: 1 -->
