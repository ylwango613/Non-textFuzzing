Now I have sufficient context for a complete analysis. Let me trace the full OOB read path.

**Analysis Summary:**

The file is 153 lines. `ff_h264_loop_filter_strength_msa` calls the macro `h264_loop_filter_strength_iteration_msa` twice:
1. `(edges, step, …, 1, -8, zero)` — dir=1
2. `(32, 8, …, 0, -1, one)` — dir=0, hardcoded

Both calls run 4 iterations when `edges=4` (standard non-16x16 MB), with `step=8` (after the `<<= 3` shift).

At the last iteration (`b_idx=24`): `ref_t = (uint8_t*)ref + 24`.

In **bidir=1 (B-frame)** mode, the macro executes:
- `ref_0 = LD_SB(ref_t + 12)` → offset 36, reads 16 bytes → ref[36..51] ✓ within 80 bytes
- `ref_1 = LD_SB(ref_t + 52)` → **offset 76, reads 16 bytes → ref[76..91]**
  - `ref_cache` is `int8_t[2][40]` = 80 bytes; bytes 80–91 are **12 bytes OOB**, reading into adjacent `mvd_cache`

For the first call (`d_idx=-8`, `d_idx_52=44`):
- `ref_3 = LD_SB(ref_t + d_idx_52)` → offset 68, reads 16 bytes → ref[68..83]: **4 bytes OOB**

For the second call (`d_idx=-1`, `d_idx_52=51`):
- `ref_3 = LD_SB(ref_t + d_idx_52)` → offset 75, reads 16 bytes → ref[75..90]: **11 bytes OOB**

The OOB bytes come from adjacent struct field `mvd_cache` (valid mapped memory, no crash). The corrupted values feed into bS but are bounded to 0–2 by `min_u_b(out, cnst_2)` before being written, so there is **no secondary OOB write** into `tc0_table`.

The actual `non_zero_count_cache` underlying buffer is 120 bytes (`uint8_t[15*8]`), so the nnz accesses that appeared OOB against the 40-byte parameter declaration are actually within bounds at the call site.

---

## VULN: OOB Read in MIPS MSA H.264 Deblocking Filter (ref_cache overread in bidir mode)
- **漏洞类别**: memory-safety
- **函数**: h264_loop_filter_strength_iteration_msa() (macro), ff_h264_loop_filter_strength_msa()
- **行号**: 47-100 (macro body), 118-152 (function)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 3.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Low
- **攻击向量**: crafted H.264 B-frame media file
- **外部触发路径**: ffmpeg -i <crafted_h264_bframe.mp4> -f null - → avformat_open_input() → avcodec_send_packet() → ff_h264_decode_mb_cabac/cavlc() → ff_h264_filter_mb() → h->h264dsp.loop_filter_strength() → ff_h264_loop_filter_strength_msa() → h264_loop_filter_strength_iteration_msa macro → LD_SB(ref_t + 52) OOB read
- **描述**: 在 `h264_loop_filter_strength_iteration_msa` 宏中，当 `bidir=1`（B 帧）且 `edges=4`（非 16x16 宏块）时，循环最后一次迭代（b_idx=24）中 `ref_t = (uint8_t*)ref + 24`。宏中 `LD_SB(ref_t + 52)` 使用 MSA 128 位 SIMD 加载指令从偏移 76 开始读取 16 字节，但 `ref_cache` 仅为 `int8_t[2][40]` = 80 字节；该指令越界读取 ref[80..91]，即相邻结构体字段 `mvd_cache` 的前 12 字节。第一次宏调用（d_idx=-8）中 `LD_SB(ref_t + d_idx_52)` 越界 4 字节，第二次调用（d_idx=-1）中越界 11 字节。由于读取结果经过 `min_u_b(..., cnst_2)` 饱和截断（限制为 0–2），最终写入 bS 的值在合法范围内，不产生二次越界写。
- **触发条件**: 构造一个包含 B 帧（bidir=1，`list_count==2`）且宏块类型为非 16x16（使得 `edges=4`）的 H.264 码流，在 MIPS 架构（MSA 扩展）上用 FFmpeg 解码，解码后对帧进行 deblocking 时触发。
- **安全影响**: 越界读取相邻结构体字段（mvd_cache）数据，属有效映射内存，不会直接导致进程崩溃。OOB 数据仅影响去块滤波强度（bS）计算的正确性，不产生内存破坏或信息泄露路径。实际安全影响为轻微信息混淆（deblocking 输出质量下降），在极端内存布局下理论上可能读取相邻帧的残差运动数据。

<!-- AUDIT_PROMPT_VERSION: 1 -->
