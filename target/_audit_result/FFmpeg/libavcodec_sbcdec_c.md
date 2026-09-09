The analysis is complete. Line 176 uses `consumed > len * 8` (strict greater-than) instead of `consumed >= len * 8`. When `consumed` equals exactly `len * 8` at the start of a bit-read iteration, the guard is false and `data[consumed >> 3]` = `data[len]` — one byte past the end of the heap-allocated packet buffer — is read.

The two earlier length checks on lines 120 and 135 use `<` correctly for the joint-stereo flag and scale-factor sections. Only the innermost per-bit guard on line 176 has the off-by-one.

An attacker can craft an SBC packet whose scale-factor and bitpool values cause `bits[ch][sb]` to be non-zero for a subband where the first bit access falls at bit position `len*8` exactly. The CRC covers only the 4-byte header + scale factors, not the audio bit payload, so the attacker can freely choose payload length and scale-factor values while still passing CRC validation. The leaked byte influences `audio_sample` through the subsequent expression, which might allow up to 1 bit of adjacent heap memory to be exfiltrated through decoder output in server-side transcoding scenarios.

## VULN: Off-by-One OOB Heap Read in `sbc_unpack_frame` Bit-Read Guard
- **漏洞类别**: memory-safety
- **函数**: sbc_unpack_frame()
- **行号**: 175-183
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted SBC media file / Bluetooth audio stream
- **外部触发路径**: `ffmpeg -i <crafted.sbc> -f null -` → `avformat_open_input()` → demuxer read loop → `avcodec_send_packet()` → `sbc_decode_frame()` → `sbc_unpack_frame(avpkt->data, &sbc->frame, avpkt->size)` → per-bit read loop at line 175
- **描述**: The innermost bit-read guard at line 176 uses a strict greater-than comparison (`consumed > len * 8`) instead of greater-than-or-equal (`consumed >= len * 8`). When `consumed` equals exactly `len * 8` at the start of a bit-reading iteration — meaning all packet bytes have been consumed — the check evaluates to `false` and the code falls through to `data[consumed >> 3]` = `data[len]`, a 1-byte read one position past the end of the heap-allocated `avpkt->data` buffer. `len` is `avpkt->size` (the packet byte count), so valid indices are `data[0..len-1]`; `data[len]` is out of bounds. The two earlier size checks at lines 120 and 135 (which use `<` correctly) guard only the joint-stereo flags and scale-factor fields; they do not protect the audio bit payload loop. The SBC CRC (line 151) covers only the 4-byte header and scale factors, not the audio bit payload, so an attacker can construct any audio payload while still passing CRC validation and triggering this path.
- **触发条件**: 攻击者构造一个 SBC 帧，通过选择 scale_factor 和 bitpool 字段（这些字段受 CRC 保护，但 CRC 可由攻击者正确计算），使 `ff_sbc_calculate_bits` 对某个 subband 分配非零 bits 值，同时令该 subband 的第一个 bit 读取恰好落在 `consumed == len * 8` 处。攻击者完全控制音频载荷的长度（即数据包 `avpkt->size`），因此可以精确定位越界读取发生的时刻。
- **安全影响**: 1 字节堆内存越界读取（`avpkt->data[avpkt->size]`）。在堆布局可预测的环境（如服务器端媒体转码管线）中，每个精心构造的 SBC 数据包可泄漏相邻堆分配中的 1 字节数据（潜在信息泄露）。该字节进入 `audio_sample` 计算，最终写入解码帧缓冲区；若转码输出被攻击者读取，则可能构成 oracle，逐字节推断堆内存内容。直接导致崩溃的概率较低（取决于 allocator 对 padding 的处理），最坏情况为信息泄露（C:L），不直接导致 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
