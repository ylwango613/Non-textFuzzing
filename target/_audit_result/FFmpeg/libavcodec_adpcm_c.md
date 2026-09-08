The analysis is complete. I have confirmed one real memory safety vulnerability in `decode_adpcm_ima_hvqm4`.

**Root cause proof for the off-by-one OOB write (mono, frame_format=1 or 3):**

- `get_nb_samples`: `nb_samples = (buf_size − 8) × 2 / 1` (always even, call it N)
- `ff_get_buffer` allocates exactly N `int16_t` values in `frame->data[0]`
- `decode_adpcm_ima_hvqm4` called with `samples_to_do = N`, `st = 0` (mono)
- Line 647–650: predictor-loop runs once (ch=0 only), writes 1 sample, then `samples_to_do--` → N−1
- Line 653: `i += 1+(!st) = 2`; for N−1 (odd), i visits 0, 2, …, N−2 → **N/2 iterations**, each writing **2 samples** → N samples
- Total written: 1 + N = **N+1 samples → 2-byte heap OOB write**

The same analysis applies for frame_format=3 (skip=9 instead of 8, still produces an even nb_samples).

---

## VULN: decode_adpcm_ima_hvqm4 mono off-by-one heap OOB write
- **漏洞类别**: memory-safety
- **函数**: decode_adpcm_ima_hvqm4()
- **行号**: 647-658
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_file> -f null - → avformat_open_input() → avcodec_send_packet() → adpcm_decode_frame() → get_nb_samples()[computes nb_samples=(buf_size-8)*2 for mono ff=1] → ff_get_buffer()[allocates N int16_t values] → decode_adpcm_ima_hvqm4()[writes N+1 int16_t values → 2-byte heap OOB]
- **描述**: 在 `decode_adpcm_ima_hvqm4()` 中，当处理单声道（channels=1）且 `frame_format` 为 1 或 3 时，存在精确的 off-by-one 堆溢出。`get_nb_samples()` 计算 `nb_samples = (buf_size − skip) × 2`（始终为偶数 N），`ff_get_buffer` 据此分配 N 个 `int16_t` 的输出缓冲区。随后 `decode_adpcm_ima_hvqm4` 被以 `samples_to_do = N` 调用：第 647–650 行的 predictor 循环写入 1 个样本并将 `samples_to_do` 减 1（变为 N−1，奇数）；第 653 行的主循环步长为 2（`i += 1+(!st)` 且 `st=0`），对于 N−1（奇数）共执行 N/2 次，每次写 2 个样本，共写 N 个。合计写入 N+1 个样本，而缓冲区仅有 N 个，造成 2 字节堆溢出写。溢出的值由攻击者通过构造 packet 中最后一个 nibble 控制（`ff_adpcm_ima_qt_expand_nibble` 输出）。
- **触发条件**: 构造一个包含 `ADPCM_IMA_HVQM4` 单声道音频流的媒体文件（如 AVI），其中音频包头部的前 2 字节 `frame_format` 字段设为 1 或 3，且 packet 总长度大于 9（frame_format=3）或 8（frame_format=1）字节以确保 nb_samples > 0。
- **安全影响**: 攻击者可将 2 字节任意值写入 heap 分配缓冲区末尾之后的相邻内存，可能破坏紧邻的堆元数据或对象指针，在有利的堆布局下可导致远程代码执行（RCE）；最差情况为进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
