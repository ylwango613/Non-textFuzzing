Based on my thorough analysis of the 372-line file, including:
- Full read of `nvdec_hevc.c`
- Verification of `NVDECContext` field types in `nvdec.h` (`bitstream_len` is `int`, `size` parameter is `uint32_t`)
- Tracing `raw_size` origin through `h2645_parse.h` (int) → `hevcdec.c` line 3054 → `nvdec_hevc_decode_slice`
- Verification that scan tables are compile-time constants with known bounds
- Verification that `max_sub_layers` is validated ≥ 1 in the SPS parser
- Verification that tile/DPB/reference-frame bounds checks are correct

The only memory-safety issue is the integer overflow at lines 282–283. All other array accesses use compile-time bounds or explicit guards.

## VULN: Integer Overflow in bitstream accumulation leading to heap underallocation and OOB write
- **漏洞类别**: memory-safety
- **函数**: nvdec_hevc_decode_slice()
- **行号**: 282-295
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.3 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -hwaccel nvdec -i <crafted.hevc> -f null - → avformat_open_input() → avcodec_send_packet() → hevc_decode_frame() → decode_slice_data() → FF_HW_CALL(decode_slice, nal->raw_data, nal->raw_size) → nvdec_hevc_decode_slice()
- **描述**: 在 `nvdec_hevc_decode_slice` 中，第 282–283 行的表达式 `ctx->bitstream_len + size + 3` 以 `uint32_t` 精度计算（C 整数提升将 `int` 的 `ctx->bitstream_len` 转换为 `uint32_t`），随后作为 `size_t min_size` 传给 `av_fast_realloc`。`ctx->bitstream_len` 是 `int`（`NVDECContext.bitstream_len`），`size` 是 `uint32_t`。当同一帧的第一个切片 `size ≈ INT_MAX`（≈2GB）时，`ctx->bitstream_len += size + 3` 发生有符号整数上溢（UB），导致 `bitstream_len` 以二补数方式回绕为约 `0x80000002`（即 −2147483646 as int）。第二次调用若 `size ≥ 0x7FFFFFFB`，则 `0x80000002 + size + 3` 在 `uint32_t` 域中溢出至接近 0 的小值（如 0 或 4），使 `av_fast_realloc` 仅分配极少字节。随后第 294 行的 `AV_WB24` 和第 295 行的 `memcpy(..., buffer, size)` 写入负偏移（`ctx->bitstream_internal + bitstream_len`，其中 `bitstream_len` 为负值）处大量数据，造成堆越界写入。
- **触发条件**: 攻击者构造一个 HEVC 码流文件，其中单帧包含两个超大切片 NAL 单元，各自 `raw_size` 接近 INT_MAX（约 2GB），使得两次累积的总量令 `uint32_t` 算术溢出。需要受害者启用 NVDEC 硬件加速路径（`-hwaccel nvdec` 或等价配置）且拥有 NVIDIA GPU。
- **安全影响**: 堆越界写入（OOB write）；在理想化条件下可能实现任意代码执行（RCE），实践中因需 4GB+ 文件及 NVDEC 硬件支持，利用难度极高，最可能的结果为崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
