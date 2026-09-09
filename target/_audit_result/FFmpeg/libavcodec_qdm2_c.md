I now have all the information needed. Let me write the final audit report.

**Batch 1 (lines 1–500):** Noted `qdm2_decode_sub_packet_header` reads `sub_packet->size` (up to 16-bit, 65535 max) from the bitstream without validating against remaining buffer length. `sub_packet->data` is set to the current bitstream position.

**Batch 2 (lines 500–1000):** `fix_coding_method_array` has a theoretical OOB `memset` at indices `[j+k]` where `j+k` can exceed array dimension 64 — but the trigger condition (`coding_method[ch][sb+1] > coding_method[ch][sb]`) is never satisfied because `coding_method_table` (all 5 rows) is strictly non-increasing with `sb`. Not practically exploitable.

**Batch 3 (lines 1000–1500):** Key finding confirmed: `qdm2_decode_super_block` at lines 1192 and 1230 calls `init_get_bits8(&gb, header.data, header.size)` where `header.size` is attacker-controlled (0–65535) with **no validation** that `header.size ≤ compressed_size − header_data_offset`. `init_get_bits8` accepts any `byte_size` from 0 to `INT_MAX/8` without checking the actual backing buffer size. The inner subpacket-parse loop then calls `qdm2_decode_sub_packet_header` which executes unconditional `get_bits` reads from this oversized GetBitContext, reading beyond `q->compressed_data + compressed_size`.

Also found: `process_subpacket_12` line 1101 passes `length=0` instead of `node->packet->size` to `init_get_bits8` — functional decoding error only; all subsequent bit reads are `get_bits_left`-guarded, so no memory-safety impact.

**Batch 4 (lines 1500–1961):** No additional memory-safety issues. `qdm2_calculate_fft` and `qdm2_synthesis_filter` accesses verified within bounds. `qdm2_decode_init` extradata parsing is properly bounds-checked.

**`init_get_bits8` / `init_get_bits` verification:** The function accepts any `byte_size` in `[0, INT_MAX/8]` — it only rejects values that overflow `INT_MAX`. A `header.size` of 65535 → 524,280 bits accepted without error. Reads then proceed using `AV_RL32(s->buffer + (s->index>>3))`, which accesses far beyond the actual `compressed_data` buffer once `index` exceeds actual data length.

---

## VULN: OOB Heap Read via Unvalidated header.size in qdm2_decode_super_block
- **漏洞类别**: memory-safety
- **函数**: `qdm2_decode_super_block()`
- **行号**: 1181–1243
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (MOV/M4A/QT container with QDM2 audio)
- **外部触发路径**: `ffmpeg -i crafted.mov -f null -` → `avformat_open_input()` → `mov_read_packet()` → `avcodec_send_packet()` → `qdm2_decode_frame()` → `qdm2_decode()` → `qdm2_decode_super_block()` → `init_get_bits8(&gb, header.data, header.size)` (line 1192/1230)
- **描述**: 在 `qdm2_decode_super_block` 中，首先用 `qdm2_decode_sub_packet_header` 从攻击者控制的压缩数据流读取 `header.size`（最大 16 位，即 65535），随后在第 1192 行和循环内第 1230 行两次调用 `init_get_bits8(&gb, header.data, header.size)`。`init_get_bits8` 仅拒绝超过 `INT_MAX/8` 的值，对 65535 完全接受，创建出声称拥有 `65535 * 8 = 524280` 位的 GetBitContext。而实际上 `header.data` 指向 `q->compressed_data`（大小为 `checksum_size`，最小为 2 字节）内某偏移处，`compressed_size - header_data_offset` 可能仅剩几个字节。此后，在子包解析循环（行 1234 的 `skip_bits`，行 1242 的 `qdm2_decode_sub_packet_header`）中，GetBitContext 的 `get_bits_left` 基于攻击者控制的 `header.size * 8` 返回非零值，导致 `get_bits` 系列函数以 `AV_RL32(s->buffer + (s->index>>3))` 的方式访问 `header.data` 后方远超实际分配长度的堆内存（最多达 65532 字节），形成堆越界读（OOB heap read）。读取所得的脏数据还会被存入 `packet->type`、`packet->size`、`packet->data` 等字段，并传递给后续的 `process_subpacket_9/10/11/12` 进行进一步处理，扩大信息泄露范围。
- **触发条件**: 攻击者构造如下畸形媒体文件：① extradata（QDCA chunk）中将 `checksum_size` 设置为极小值（最小 2，通过 `qdm2_decode_init` 的 `<= 1` 检查）；② 音频数据包起始处将 superblock header 的 `type` 字节的 bit 7 置 1（使 `size` 占两字节），并将 `size` 字段设为 0xFFFF（65535），远超实际剩余数据；③ 其余字节填充合法但微小的子包（保证 `packet_bytes > 0` 使循环持续，且子包类型合法避免 `AVERROR_PATCHWELCOME` 提前退出）。
- **安全影响**: 攻击者可使解码器从音频数据包缓冲区末尾之外读取最多约 65 KB 的堆内存数据（相邻堆分配内容，如其他媒体帧的解码结果、FFmpeg 内部上下文、堆元数据等），构成堆内存信息泄露（heap info-leak），可用于绕过 ASLR 等内存保护机制；在边界外数据被解释为合法子包参数并传入后续解码函数的路径下，亦可能导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
