Based on my complete multi-pass read of all 741 lines of `dnxhddec.c` and inspection of `get_bits.h` / `dnxhddata.h`, here is my assessment:

**Batch 1 (lines 1–299): Init, VLC setup, header parse up to buf_size guard.**
- `mb_height` from `AV_RB16` (user-controlled, 0–65535).
- Bounds chain: old-format → `> 68` → error; HR → `> 512` → error at line 334.
- `mb_scan_index[512]` loop at 340 writes at most index 511 — correct.

**Batch 2 (lines 300–460): mb_scan_index validation, DCT decode.**
- Check at line 344 uses **strict `<`**, not `<=`: when `mb_scan_index[i] == buf_size - data_offset` the check passes.
- `init_get_bits8` is then called with `byte_size = 0` → `size_in_bits = 0`, buffer set to `buf + buf_size`.
- Because `UNCHECKED_BITSTREAM_READER 1` is defined (line 35), `UPDATE_CACHE_BE` reads `AV_RB32(buf + buf_size + 0)` — 4 bytes past end of packet. Impact is mitigated if `AV_INPUT_BUFFER_PADDING_SIZE` padding is present, but not guaranteed in all call paths.

**Batch 3 (lines 461–618): macroblock decode, idct_put writes.**
- `x` bounded by `mb_width`, `y` by `mb_height`, line 322 cross-checks against `ctx->height` — no frame-buffer OOB write found.
- DCT block `i` bounded by check at line 437 (`> 63`), `scale[i]` and `permutated_scantable[i]` accesses are within their 64-element arrays.

**Batch 4 (lines 619–741): frame decode loop, interlaced second field.**
- `first_field` flag and `ff_set_dimensions` / `ff_thread_get_buffer` re-allocation on dimension change prevent frame-buffer overwrite.
- `buf_size -= coding_unit_size` with prior guard at line 295 prevents underflow.

---

## VULN: Off-by-one in mb_scan_index bounds check enables heap OOB read
- **漏洞类别**: memory-safety
- **函数**: dnxhd_decode_header()
- **行号**: 344-349
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.0 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted DNxHD/VC3 media file
- **外部触发路径**: `ffmpeg -i <crafted.dnxhd> -f null -` → `avformat_open_input()` → `ff_read_packet()` → `dnxhd_decode_frame()` → `dnxhd_decode_header()` (off-by-one passes) → `dnxhd_decode_row()` → `init_get_bits8(..., 0)` → `UPDATE_CACHE` reads past packet buffer
- **描述**: `dnxhd_decode_header()` 第 344 行对 `mb_scan_index[i]` 的边界检查使用严格小于（`<`），而非小于等于（`<=`）。当攻击者将某行的 `mb_scan_index[i]` 精确设置为 `buf_size - ctx->data_offset`（即剩余字节数）时，检查通过。随后 `dnxhd_decode_row()` 以 `offset == ctx->buf_size` 调用 `init_get_bits8(&row->gb, ctx->buf + offset, 0)`，将 GetBitContext 的 `buffer` 指针设置为 `buf + buf_size`（包缓冲区末尾的后一字节）且 `size_in_bits = 0`。由于文件顶部定义了 `#define UNCHECKED_BITSTREAM_READER 1`（第 35 行），`UPDATE_CACHE_BE` 宏展开为 `AV_RB32(gb->buffer + (index >> 3))` 时不做边界检查，直接从 `buf + buf_size` 读取 4 字节——越出堆上包缓冲区末尾。
- **触发条件**: 构造一个合法结构的 DNxHD 帧，使某一行的 `mb_scan_index[i]`（位于帧头偏移 `0x170 + i*4`，HR 格式下最多 512 行）恰好等于 `avpkt->size - data_offset`，即恰好指向包缓冲区尾部。满足 `buf_size >= ctx->data_offset` 及 `mb_height <= 512` 的其他约束条件即可通过所有前置检查。
- **安全影响**: 堆越界读取（最少 4 字节，随着解码继续可能更多）。若相邻堆内存包含指针或密钥等敏感数据，可造成信息泄露（heap info leak）。在无 ASAN/HWASAN 保护的场景下不会立即崩溃（FFmpeg 包通常带有 `AV_INPUT_BUFFER_PADDING_SIZE` 填充，使得实际读取命中填充区；若上层调用者未添加填充则可触发崩溃或读取相邻分配块内容）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
