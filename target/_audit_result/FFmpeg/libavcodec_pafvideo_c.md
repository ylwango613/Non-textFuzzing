Now I have full context. Let me analyze the critical findings:

**Finding 1 — Off-by-one in `decode_0` opcodes bounds check (line 234):**
- `opcode_size` is a uint16 read from the packet (attacker-controlled).
- `opcodes = pkt + bytestream2_tell(&c->gb)` points into pkt->data; valid indices are `[0, opcode_size)`.
- The loop check is `if (op > opcode_size)` — should be `>=`.
- When `op == opcode_size`, the check is **false**, and `opcodes[op]` reads 1 byte past the valid region.
- If the opcodes are at the tail of the packet (`tell + opcode_size == pkt->size`), this reads 1 byte past `pkt->data[pkt->size-1]` — a heap OOB read.

**Finding 2 — Integer overflow in `frame_size` / `video_size` calculation (lines 106-107):**
- `av_image_check_size2` (line 98) is called with `FFALIGN(avctx->height, 256)` and validates `width * FFALIGN(height, 256)`. Frame_size is safe.
- `c->video_size = avctx->width * avctx->height` (line 107) — since `height ≤ FFALIGN(height,256)`, and frame_size is bounded by av_image_check_size2, video_size is also bounded. **No overflow here.**

**Finding 3 — `set_src_position` offset bounds:**
- Callers check `src + 3*width+4 > send` immediately after — guarded. No OOB write.

Only Finding 1 is a genuine memory-safety vulnerability:

## VULN: Off-by-one OOB Read on Opcodes Buffer in decode_0
- **漏洞类别**: memory-safety
- **函数**: decode_0()
- **行号**: 234-240
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PAF video media file
- **外部触发路径**: `ffmpeg -i <crafted.paf> -f null -` → `avformat_open_input()` → demuxer → `avcodec_send_packet()` → `paf_video_decode()` → `decode_0()` → OOB read at `opcodes[op]` when `op == opcode_size`
- **描述**: 在 `decode_0()` 的 opcodes 循环中，边界检查使用 `op > opcode_size` 而非 `op >= opcode_size`（第 234 行）。`opcode_size` 是从数据包中以 `uint16_t` 读取的攻击者可控值（第 220 行：`bytestream2_get_le16`）。`opcodes` 指针指向 `pkt->data` 中的 `opcode_size` 字节区域（第 226 行）。当 `op == opcode_size` 时，检查 `op > opcode_size` 为假，程序继续在第 236/239 行执行 `opcodes[op]`，读取了 opcodes 缓冲区末尾之后 1 字节。若 opcodes 段位于数据包末尾（`tell + opcode_size == pkt->size`），则该读取越过 `pkt->data` 堆缓冲区 1 字节，构成堆外读。
- **触发条件**: 攻击者构造一个 PAF 视频数据包（code & 0x0F == 0 触发 decode_0），其中 `opcode_size`（第 220 行读取的 uint16）设置为 `(width/4 * height/4) / 2`（即恰好消耗完所有 opcode 字节的数量），并令 opcodes 段紧贴数据包末尾，之后无更多字节，使得 `opcodes[opcode_size]` 读取超出堆分配边界。
- **安全影响**: 堆外读 1 字节，可能泄露相邻堆内存内容（信息泄露），或在 opcodes 段位于内存页末尾时触发 SIGSEGV（DoS）。与堆布局原语结合，有潜在的信息泄露利用价值。

<!-- AUDIT_PROMPT_VERSION: 1 -->
