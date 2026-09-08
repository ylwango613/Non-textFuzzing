The analysis is complete. The integer overflow at line 790 is confirmed as a real exploitable path. Here is the full analysis:

**Overflow mechanics at line 790:**
- `prestream_size` is `unsigned int`; `4 * AV_RL32(...)` is a 32-bit multiply
- If `AV_RL32(buf + bitstream_size + 4)` == `0x40000000`, result wraps to `0`
- With `bitstream_size` crafted to be `length - 12`:
  - Line 793 check: `0 + (length-12) + 12 == length` → passes (equal)
  - Line 794 check: `0 > (1<<26)` → false → passes
- `prestream = buf + length` (one past end of heap buffer)
- `read_huffman_tables(f, buf+length, 0)` called → lines 635-636: `start = *ptr++; end = *ptr++;` read 2 bytes past the packet buffer → **heap OOB read**

## VULN: Integer Overflow in decode_i_frame Leads to Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: decode_i_frame()
- **行号**: 790-800 (root cause line 790; OOB read triggered at read_huffman_tables:635-636)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted .4xm media file
- **外部触发路径**: `ffmpeg -i crafted.4xm -f null -` → `avcodec_decode_video2()` → `decode_frame()` (4xm.c:837) → `decode_i_frame()` (4xm.c:945) → `read_huffman_tables()` (4xm.c:800) → OOB read at 4xm.c:635
- **描述**: 在 `decode_i_frame`（行 790），`prestream_size` 被计算为 `4 * AV_RL32(buf + bitstream_size + 4)`，这是一个 32 位无符号乘法，当 `AV_RL32()` 返回值 ≥ `0x40000000` 时会发生整数回绕（wraps to 0 or near-zero）。攻击者同时将 `bitstream_size`（来自文件的 `AV_RL32(buf)`）设为 `length - 12`，使得下游校验 `prestream_size + bitstream_size + 12 != length`（行 793）完全通过（0 + (length-12) + 12 == length），以及 `prestream_size > (1 << 26)` 也为 false。随后，`prestream = buf + bitstream_size + 12 = buf + length`，即指向包数据末尾后一字节。`read_huffman_tables(f, prestream, 0)` 被调用时，`buf_size=0`，使得 `ptr_end = ptr = buf+length`；行 635 `start = *ptr++` 和行 636 `end = *ptr++` 立即对堆上分配的包缓冲区进行越界读取。
- **触发条件**: 攻击者构造一个 `ifrm` 类型的 4XM 视频帧（`frame_4cc == "ifrm"`），满足：① `AV_RL32(buf)` = `frame_size - 12`（使 bitstream_size = length - 12）；② 文件偏移 `buf + bitstream_size + 4` 处的 4 字节值为 `0x40000000`（或任意使 4× 乘法回绕至 0 或小值的倍数）。只需用户用 ffmpeg/ffplay 打开该文件即可触发。
- **安全影响**: 堆越界读取（2+ 字节），可导致进程崩溃（高可用性影响/DoS）；在特定堆布局下，越界字节的值会作为 Huffman 频率表索引被使用（`start/end` 用于 `frequency[i]`），进一步在堆上读取更多字节，可能造成堆内存布局泄露（信息泄露）。结合其他原语可能用于构造更复杂攻击链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
