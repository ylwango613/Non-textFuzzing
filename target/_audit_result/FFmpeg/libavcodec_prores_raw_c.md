I've now confirmed the critical details from the `bytestream.h` implementation:
- `bytestream2_get_byteu` (suffix `u` = unchecked) expands to `bytestream_get_byte(&g->buffer)` — it does `(*b)++; return AV_RB8(*b-1)` with NO bounds check.
- `bytestream2_get_be16` (no `u`) IS checked — returns 0 safely when buffer is empty.

**Root cause confirmed:** In `decode_tile()` at lines 262–263, two `bytestream2_get_byteu` calls read unconditionally. In `decode_frame()` (lines 500–505), tile size is validated only for upper bounds (not ≥ packet size, not offset overflow), with **no minimum size check**. A tile with `size = 0` placed so that `offset = avpkt->size − 1` satisfies all existing guards and causes the second `bytestream2_get_byteu` to read one byte past `avpkt->data + avpkt->size` — a heap out-of-bounds read.

## VULN: Heap OOB Read in decode_tile() via Unchecked bytestream2_get_byteu on Undersized Tile
- **漏洞类别**: memory-safety
- **函数**: decode_tile()
- **行号**: 262-263
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted ProRes RAW media file
- **外部触发路径**: ffmpeg -i <crafted.mov> -f null - → avformat_open_input() → mov demuxer → avcodec_send_packet() → decode_frame() [prores_raw.c] → decode_tiles() (via execute2) → decode_tile() → bytestream2_get_byteu() [line 262-263, unchecked read past tile buffer]
- **描述**: `decode_tile()` 使用两次 `bytestream2_get_byteu`（无 `u` 前缀的 checked 版与之不同，`u` 版无边界检查，直接解引用 `gb->buffer++`）读取 tile 的前两个字节（header_len 和 scale）。`decode_frame()` 在将 tile 注册到 `s->tiles[]` 时，对 tile size 仅做了上界校验（`size >= avpkt->size`）和偏移溢出校验（`offset > avpkt->size - size`），但**没有最小尺寸检查**（如 `size < 8`）。当攻击者将某个 tile 的 size 设置为 0 或 1、并使其 offset 满足 `offset = avpkt->size - 1` 时，第二次 `bytestream2_get_byteu` 会读取 `*(avpkt->data + avpkt->size)`，即堆分配的 `avpkt->data` 缓冲区末尾之后的第一个字节，造成堆越界读取（heap OOB read）。
- **触发条件**: 构造一个合法 ProRes RAW 容器，在 tile size 表中将最后一个 tile 的 size 设为 0，同时通过调整前面各 tile 的 size 使得最后 tile 的 `offset` 恰好等于 `avpkt->size - 1`。该 packet 通过现有所有边界检查（`offset < avpkt->size` 通过；`0 < avpkt->size` 通过；`offset <= avpkt->size - 0` 通过），但 `decode_tile()` 内的两次无检查读取越出 tile 缓冲区，且第二次越出整个 `avpkt->data` 堆分配。
- **安全影响**: 堆越界读取最多 2 字节（具体取决于 tile size）。如果越界访问落在未映射页边界，会触发 SIGSEGV 导致 DoS；如果位于同一堆页，可泄露相邻堆内存内容（1–2 字节信息泄露），在特定堆布局下可能暴露堆元数据，为进一步利用（如绕过 ASLR）提供信息。

<!-- AUDIT_PROMPT_VERSION: 1 -->
