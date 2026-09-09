Now I have a complete picture. Let me trace the multi-stream pointer advancement path to confirm the OOB read impact:

**Key finding summary:**

In `ff_opus_parse_packet` (parse.c line 225, CBR self_delimiting path):
- `pkt->frame_count * frame_bytes + padding` is an `int` expression
- `padding` can legitimately reach `INT_MAX` via `xiph_lacing_full`
- `pkt->frame_count * frame_bytes` is at most 48×1275=61200
- Sum `INT_MAX + 61200` overflows to a negative int (e.g., −2147422703)
- The bounds check `negative_int > end - ptr` evaluates false → check bypassed
- `end = ptr + negative_value` sets `end` ~2 billion bytes before `buf`
- `pkt->packet_size = buf_size = end - buf` becomes a large negative int
- In `dec.c:590`, `buf += s->packet.packet_size` advances `buf` backward by ~2 billion bytes
- The next sub-packet is parsed from an out-of-bounds memory location

The VBR path at line 207 has the same overflow pattern (`len + total_bytes + padding`), and the same `packet_size` corruption and OOB read outcome.

## VULN: Integer overflow in opus self-delimiting packet size check leads to heap OOB read
- **漏洞类别**: memory-safety
- **函数**: ff_opus_parse_packet()
- **行号**: 207-211, 223-228 (libavcodec/opus/parse.c); 590-591 (libavcodec/opus/dec.c)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (Ogg Opus with multiple streams)
- **外部触发路径**: `ffmpeg -i crafted.ogg -f null -` → `avformat_open_input()` → `ogg demuxer` → `opus_decode_packet()` (dec.c:477) → `ff_opus_parse_packet()` (parse.c:85) → signed integer overflow at line 225 / 207 → corrupted `pkt->packet_size` → `dec.c:590` `buf += s->packet.packet_size` → OOB read in next `ff_opus_parse_packet()` call
- **描述**: In `ff_opus_parse_packet()`, when `self_delimiting=1` (set when `nb_streams > 1`, i.e., a multi-stream Ogg Opus file) and the packet uses code=3 (multi-frame) with the padding flag set, the function reads a padding size via `xiph_lacing_full()`, which can legitimately return values up to `INT_MAX` (the loop guard `val > INT_MAX - 254` permits `val = INT_MAX - 254`, and adding a final byte value of 254 yields `INT_MAX`). For the CBR self-delimiting branch (line 223-228), the guard is `pkt->frame_count * frame_bytes + padding > end - ptr`; the left-hand side is a 32-bit signed `int` expression. With `padding ≈ INT_MAX` and `frame_count * frame_bytes = 48 × 1275 = 61200`, the sum overflows to a large negative int (e.g., −2147422703), causing the bounds check to evaluate as `negative > positive = false`, silently bypassing it. The function then computes `end = ptr + (overflowed negative value)`, placing `end` approximately two billion bytes before `buf`. Consequently `buf_size = end - buf` is a large negative `ptrdiff_t` that truncates to a negative `int`, stored into `pkt->packet_size`. Back in `opus_decode_packet()` (dec.c:590), the decoder advances with `buf += s->packet.packet_size`, moving `buf` ~2 billion bytes backward in virtual address space. The subsequent call `ff_opus_parse_packet(&s->packet, buf, buf_size, …)` at dec.c:567 then reads from this wildly out-of-bounds pointer, constituting a heap out-of-bounds read. The identical overflow pattern exists in the VBR self-delimiting path at lines 207-211 (`len + total_bytes + padding`).
- **触发条件**: 攻击者需构造一个多流 Ogg Opus 文件（extradata 中 `map_type ∈ {1,2,255}`，`streams ≥ 2`），使得解码器以 `self_delimiting=true` 模式解析首个子流。该子流的第一个 Opus 包使用 code=3、CBR、padding 标志位置 1，并在 padding lacing 字段中编码一个接近 `INT_MAX` 的填充大小（需要约 840 万字节的 Xiph lacing 序列，即约 8 MB 的 padding lacing 数据）；随后紧跟 CBR 帧大小（1–2 字节）及合法帧载荷。总包大小约 8–9 MB，在 Ogg 多页封装下可合法传输。
- **安全影响**: 堆越界读，可造成进程崩溃（DoS），或通过堆/栈内存布局信息泄露辅助进一步利用。在特定内存布局下，越界读到的数据可能被后续解码逻辑消费，潜在地将信息泄露扩大为远程代码执行原语。

<!-- AUDIT_PROMPT_VERSION: 1 -->
