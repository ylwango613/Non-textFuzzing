Now I have full context. Let me trace the complete data flow carefully.

**Demuxer path (dsicin.c):**
- Line 188: `pkt_size = (palette_type + 3LL) * hdr->pal_colors_count + hdr->video_frame_size;`
- Line 194: `av_new_packet(pkt, 4 + pkt_size)` — allocates exactly that many bytes
- Lines 206-211: `avio_read(pb, &pkt->data[4], pkt_size)` — if file is short, `av_shrink_packet(pkt, 4 + ret)` shrinks the packet to as few as 4 bytes

**Decoder path (dsicinvideo.c):**

With `pal_colors_count=0` and `video_frame_size=0` (or any small k < 15) and `video_frame_type` 35/36/37, the demuxer sends a packet of exactly `4 + k` bytes (or as small as 4 bytes after a short-read + shrink). The decoder then:
- `buf = avpkt->data`, `buf_size = 4 + k`
- `buf += 4` → `buf` now points 1 past or beyond the last valid byte when `k=0`
- `bitmap_frame_size = k = 0`

For frame types 35, 36, 37 → `cin_decode_huffman(buf, 0, ...)` is called.

**Inside `cin_decode_huffman` line 104:**
```c
memcpy(huff_code_table, src, 15);   // reads 15 bytes from buf, but 0 valid bytes remain
```
This reads up to 15 bytes past the end of the `avpkt->data` heap allocation → **heap OOB read**.

**Inside the loop (lines 111, 120):** Even with `bitmap_frame_size ≥ 15`, if the last byte in src has upper nibble `0xF` (lines 109→111) or lower nibble `0xF` (line 119→120), an extra `*src++` fires without checking `src < src_end`.

## VULN: cin_decode_huffman heap OOB read — missing src_size check before 15-byte memcpy
- **漏洞类别**: memory-safety
- **函数**: cin_decode_huffman()
- **行号**: 104-105
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted .cin media file
- **外部触发路径**: `ffmpeg -i crafted.cin -f null -` → `avformat_open_input()` → `cin_read_packet()` → `av_new_packet(pkt, 4+0)` (when `video_frame_size=0`, `pal_colors_count=0`) → `cinvideo_decode_frame()` → `cin_decode_huffman(buf=avpkt->data+4, src_size=0, ...)` → `memcpy(huff_code_table, src, 15)` OOB
- **描述**: `cin_decode_huffman()` 在第104行无条件执行 `memcpy(huff_code_table, src, 15)`，将15字节拷贝到栈上的 `huff_code_table[15]` 数组，但从未验证 `src_size >= 15`。当 `bitmap_frame_size`（即 `src_size`）小于15时，`src` 所指向的堆缓冲区（`avpkt->data`）中只有 `src_size` 个有效字节，`memcpy` 会越界读取 `15 - src_size` 个字节，触发堆越界读（heap OOB read）。攻击者通过控制容器字段 `video_frame_size`（可设为0）和 `pal_colors_count`（设为0）以及 `video_frame_type`（设为35/36/37），使 demuxer 生成大小仅为4字节的视频包（`av_new_packet(pkt, 4)`），而解码器在推进 `buf += 4` 后以空指针调用 huffman 解码，导致 `memcpy` 从 `avpkt->data[4]` 起越过堆分配边界读取15字节。
- **触发条件**: 构造一个 CIN 格式文件，将帧头中的 `video_frame_size`（偏移4字节处的rl32字段）设置为0或小于15的值，将 `pal_colors_count`（偏移2字节处的rl16字段）设置为0，将 `video_frame_type` 设置为35、36或37（启用 huffman 路径），demuxer 生成极小视频包后解码器即触发。
- **安全影响**: 堆越界读可导致进程崩溃（DoS），并可能泄露相邻堆块中的内存内容（信息泄露）。在特定内存布局下，可辅助 ASLR 绕过，结合其他漏洞链式利用可能升级为 RCE。

## VULN: cin_decode_huffman heap OOB read — missing src_end check in decode loop
- **漏洞类别**: memory-safety
- **函数**: cin_decode_huffman()
- **行号**: 111, 120
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted .cin media file
- **外部触发路径**: `ffmpeg -i crafted.cin -f null -` → `cin_read_packet()` → `cinvideo_decode_frame()` → `cin_decode_huffman(buf, bitmap_frame_size, ...)` → 解码循环内 `*src++` 越过 `src_end`
- **描述**: `cin_decode_huffman()` 的主解码循环在外层 `while (src < src_end)` 检查之后，存在两处无边界保护的 `*src++`：（1）第109行检测到上半字节为 `0xF` 时，第111行 `huff_code = *src++` 直接读取下一字节，但此时 `src` 可能已等于 `src_end`；（2）第119行检测到下半字节为 `0xF` 时，第120行 `*dst_cur++ = *src++` 同样缺乏 `src < src_end` 保护。当攻击者构造的源数据中最后一个字节的高半字节或低半字节等于 `0xF` 时，`src` 会越过 `src_end`（即 `avpkt->data` 分配边界）读取1字节，造成单字节堆越界读（heap OOB read by 1）。
- **触发条件**: 构造一个 CIN 文件，使 `bitmap_frame_size >= 15`（绕过 Bug 1），且解码缓冲区中最后一字节的高半字节或低半字节恰好为 `0xF`。例如：设 `video_frame_size = 16`（仅含15字节huffman表+1字节数据 `0xF?` 或 `0x?F`），demuxer 生成20字节包，解码器在处理最后一个字节时越界。
- **安全影响**: 单字节堆越界读，可造成进程崩溃（DoS）或泄露紧邻堆块的1字节数据，可辅助信息泄露攻击链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
