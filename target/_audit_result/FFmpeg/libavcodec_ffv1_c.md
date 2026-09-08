Now I have all the information I need. Let me confirm the exact call sequence and vulnerability:

**Summary of findings:**

- In `decode_remap` (ffv1dec.c:300–377), after the inner `while (run1--)` loop writes the last fltmap entry at `i = end = 0xFFFFFFFF` (for 32-bit float streams), it executes `i++` (→ `i = 0x100000000`) and immediately calls `decode_current_mul(rc, state, mul, mul_count, i)` with `i = 0x100000000`.
- In `decode_current_mul` (line 291): `int ndx = (i * mul_count) >> 32` = `(0x100000000LL * 4096LL) >> 32 = 268435456`.
- `av_assert2(ndx <= 4096U)` is a **no-op** in all normal builds (requires `ASSERT_LEVEL > 1`).
- `mul[268435456]` is accessed on a local stack array of size 4097 — a massive OOB read/write ~1 GB past the array start → SIGSEGV crash.

## VULN: OOB Stack Array Access in decode_current_mul via 32-bit FFV1 remap
- **漏洞类别**: memory-safety
- **函数**: decode_current_mul() / decode_remap()
- **行号**: 289-297 (decode_current_mul), 342-371 (decode_remap inner loop, line 365 is the call site)
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (e.g., NUT/MKV container embedding FFV1 stream)
- **外部触发路径**: `ffmpeg -i <crafted_file> -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `decode_frame()` → `decode_slices()` → `decode_slice()` → `decode_remap()` → `decode_current_mul()` [OOB]
- **描述**: In `decode_remap()` (ffv1dec.c), after writing the last remap entry when `i == end == 0xFFFFFFFF` (32-bit float samples), the inner loop does `i++` making `i = 0x100000000` and immediately calls `decode_current_mul(rc, state, mul, mul_count, i=0x100000000)`. Inside `decode_current_mul`, `ndx = (i * mul_count) >> 32` is computed as `(0x100000000LL * 4096LL) >> 32 = 268435456`. The guard `av_assert2(ndx <= 4096U)` is a **compile-time no-op** in all non-ASSERT_LEVEL>1 builds. The code then reads `mul[268435456]` and conditionally writes to `mul[268435456]`, where `mul` is a local stack array of only 4097 elements (`int mul[4096+1]`). This accesses stack memory approximately 268,435,456 × 4 ≈ 1 GB above the array's base address, reliably causing a SIGSEGV crash. An attacker can craft the bitstream so that `mul_count = 4096` (bitstream field, validated only to ≤ 4096) and the multiplier values cause `i` to reach `0xFFFFFFFF` before `j` exceeds `pixel_num`, ensuring the vulnerable call is reached.
- **触发条件**: 攻击者构造一个包含 FFV1 码流的媒体文件，满足：(1) `bits_per_raw_sample = 32`（32-bit 浮点样本）且 `flt = 1`；(2) `sc->remap` 置为 1 或 2（bitstream 中编码）；(3) `mul_count = 4096`（bitstream 解码值，在 4096U 限制范围内）；(4) 编码的 multiplier 值使得在 remap 循环中，`i` 经由大步长跳跃（`current_mul` 接近 0x3FFFFFFF）快速推进到 `end = 0xFFFFFFFF`，同时 `j`（fltmap 写入计数）保持低于 `pixel_num`。最终 `i++` 后 `i = 0x100000000`，触发 `decode_current_mul` 中的 OOB 访问。
- **安全影响**: 可靠触发 SIGSEGV 崩溃（DoS）。由于访问偏移量约为 1GB，通常指向未映射内存；在极少数特殊内存布局下理论上存在 OOB 读/写原语，但实际利用 RCE 的可能性极低。主要影响为拒绝服务：任何解析攻击者控制的 FFV1 32-bit 浮点格式文件的应用（包括 ffmpeg、ffplay、使用 libavcodec 的媒体播放器）均会崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
