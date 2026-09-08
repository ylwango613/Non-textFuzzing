I have completed my full analysis of `mpc7.c` and its call chain. Here is my comprehensive finding:

**Analysis summary:**
- `mpc_CC[18+1]` (19 elements) is accessed via `(mpc_CC+1)[res]` where `res ∈ [-1,17]` — within bounds (safe).
- `mpc_SCF[256]` is accessed with `& 0xFF` mask — within bounds (safe).
- `skip_bits_long` with attacker-controlled skip value is safe due to `av_fast_padded_malloc` padding guarantees.
- Stale `bands[].res` values for `i > c->maxbands` in the quantizer loop stay within `c->Q` array bounds — logic bug only, not memory-safety.
- **Critical finding**: `c->lastframelen` is read as an unvalidated 11-bit field (0–2047) from extradata. When `last_frame != 0`, `frame->nb_samples` is overwritten with this value, but the frame buffer was allocated for only `MPC_FRAME_SIZE = 1152` samples. Downstream consumers reading `frame->nb_samples` samples will read beyond the 2304-byte-per-channel heap buffer.

---

## VULN: mpc7 lastframelen Heap OOB Read via Unchecked nb_samples
- **漏洞类别**: memory-safety
- **函数**: mpc7_decode_frame()
- **行号**: 111 (init), 210-211, 280-281 (frame decode)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted Musepack SV7 (.mpc) media file
- **外部触发路径**: `ffmpeg -i crafted.mpc -f null -` → `avformat_open_input()` → MPC demuxer sets extradata → `avcodec_open2()` → `mpc7_decode_init()` [reads unvalidated 11-bit `lastframelen` from extradata at bit offset 100] → `mpc7_decode_frame()` [allocates AVFrame for `MPC_FRAME_SIZE=1152` samples, writes 1152 samples, then unconditionally sets `frame->nb_samples = c->lastframelen` (up to 2047) when `last_frame != 0`] → downstream audio consumer reads `nb_samples` samples beyond the heap allocation
- **描述**: In `mpc7_decode_init()` (line 111), `c->lastframelen` is populated from 11 bits of the extradata stream (`get_bits(&gb, 11)`), yielding values in [0, 2047] with no upper-bound check against `MPC_FRAME_SIZE` (1152). In `mpc7_decode_frame()`, the AVFrame audio buffer is allocated at line 211 via `ff_get_buffer()` for exactly `MPC_FRAME_SIZE=1152` samples per channel (2304 bytes/channel in AV_SAMPLE_FMT_S16P). `ff_mpc_dequantize_and_synth()` writes exactly 1152 samples. At lines 280–281, when the packet's second byte (`buf[1]`, fully attacker-controlled) is non-zero, `frame->nb_samples` is overwritten with `c->lastframelen` — potentially up to 2047. Any downstream code that trusts `frame->nb_samples` and reads that many samples from `frame->extended_data[ch]` will read up to (2047 − 1152) × 2 = 1790 bytes per channel beyond the end of the heap allocation.
- **触发条件**: 攻击者需构造一个 Musepack SV7 文件，在 extradata 的第 100 位起以 11 位编码一个大于 1152 (最大可到 2047) 的 `lastframelen` 值；同时在对应的最后帧数据包的第 2 字节（`buf[1]`）设为非零以触发 `last_frame` 条件。extradata 合法性检查仅要求 `extradata_size >= 16`（line 91），不校验 `lastframelen` 上界，故构造极为简单。
- **安全影响**: 堆越界读取，最多泄露每通道约 1790 字节的堆内存内容（可能包含函数指针、堆元数据等敏感信息），构成信息泄露（CWE-200）；若越界区域跨页边界亦可导致进程崩溃（DoS）。在 ASLR 旁路场景下，此类堆泄漏可作为进一步利用的信息收集原语。

<!-- AUDIT_PROMPT_VERSION: 1 -->
