Now I have full context. Let me analyze the critical vulnerability carefully.

**Key findings:**

**Line 68**: `if (buf_size < 5) { return; }` — minimum check requires only 5 bytes.

**Line 77**: `init_get_bits(&gb, buf + 4, 100)` — initializes GetBitContext with 100 bits (12.5 bytes) starting at `buf+4`. This requires `buf_size >= 4 + 13 = 17` bytes total, but the check only enforces `buf_size >= 5` (1 payload byte after 4 header bytes).

**Bit consumption analysis:**
- `get_bits(&gb, 8)` at line 83: bits 0–7
- `skip_bits(&gb, 47)` at line 94: bits 8–54
- Conditional `get_bits(&gb, 3)` at line 97: bits 55–57
- `skip_bits(&gb, 5)` at line 109: bits 58–62 (or 55–59)
- `get_bits(&gb, 4)` at line 111 (`ratecode`): up to bit 66
- `skip_bits(&gb, 32)` at line 117: up to bit 98
- `get_bits(&gb, 1)` at line 119: bit 99 or 100

Maximum read: 100 bits = bytes buf+4 through buf+16. With `buf_size=5`, buf+5 through buf+16 are OOB.

**`ff_avs3_frame_rate_tab[ratecode]` index safety:** `ratecode = get_bits(&gb, 4)` = 0–15; the table has exactly 16 entries → always in-bounds regardless of what garbage value is read.

**Mitigating factor:** `ff_combine_frame` allocates its internal buffer with `AV_INPUT_BUFFER_PADDING_SIZE` (64) bytes of zeroed padding (parser.c:240,249). This means in the normal non-`PARSER_FLAG_COMPLETE_FRAMES` path with accumulated data, the OOB read lands in zero-padded memory. However, when `pc->index == 0` (no previously accumulated data) the original `*buf` is not modified by `ff_combine_frame` and the caller's buffer may lack the 64-byte zero padding — or when `PARSER_FLAG_COMPLETE_FRAMES` is set, `ff_combine_frame` is skipped entirely and the raw input buffer is used, which may not be padded. In either unpadded case, the OOB read causes a crash (DoS) or, on a heap-adjacent buffer, leaks adjacent heap memory.

## VULN: OOB Read in parse_avs3_nal_units Due to Insufficient Buffer Size Check
- **漏洞类别**: memory-safety
- **函数**: parse_avs3_nal_units()
- **行号**: 68-123
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted AVS3 media file
- **外部触发路径**: `ffmpeg -i <crafted.avs3> -f null -` → `avformat_open_input()` → AVS3 parser invocation → `avs3_parse()` (avs3_parser.c:150) → `parse_avs3_nal_units()` (avs3_parser.c:65) → `init_get_bits(&gb, buf + 4, 100)` + subsequent `get_bits()`/`skip_bits()` calls reading up to byte buf+16
- **描述**: `parse_avs3_nal_units()` checks `buf_size < 5` (line 68) before entering the sequence-header branch, but then calls `init_get_bits(&gb, buf + 4, 100)` (line 77), declaring a GetBitContext of 100 bits (12.5 bytes) over a buffer that may contain as few as 1 payload byte (`buf_size - 4 = 1`). Subsequent `get_bits()`/`skip_bits()` calls collectively consume up to 100 bits, accessing bytes `buf+4` through `buf+16`. `init_get_bits` does not validate that the declared `bit_size` fits within the physical allocation — it only stores the value as `size_in_bits` for limit-checking by later read calls. When the caller buffer is not zero-padded (e.g., when `PARSER_FLAG_COMPLETE_FRAMES` is set, bypassing `ff_combine_frame`'s zero-padding at parser.c:249, or when `pc->index == 0` so the original unpadded buffer is used), reads at byte offsets 5–16 of a 5-byte buffer go into adjacent heap or unmapped memory.
- **触发条件**: 攻击者构造一个以 `0x00 0x00 0x01 0xB0`（AVS3 Sequence Start Code）开头、总长度为 5–16 字节的畸形 AVS3 比特流（例如 `.avs3` 文件或封装于容器中）。当解析器在 `PARSER_FLAG_COMPLETE_FRAMES` 模式（跳过 `ff_combine_frame` 的 64 字节零填充）下处理该包，或在首次接收分段数据时 `pc->index == 0`（原始未填充缓冲区直接传入），将触发最多 12 字节的越界读取。
- **安全影响**: 最坏情况下，当读取区域为未映射内存时，进程因 SIGSEGV 崩溃（拒绝服务）；当读取区域为相邻堆内存时，可能泄露堆上敏感数据（信息泄露），包括指针值（可辅助 ASLR 绕过用于后续更严重的利用链）。在零填充路径下，行为退化为功能性错误（错误的帧率 `0/0`），不构成内存安全威胁。

<!-- AUDIT_PROMPT_VERSION: 1 -->
