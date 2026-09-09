The analysis is complete. Here is my accounting of the complete write path:

**Allocated (line 1070):**  
`video_data_max + 256×10 + 8 = video_data_max + 2568 bytes`

**Actual written (non-first frame, max codebook):**  
- `write_codebooks`: 2+4+1+1 (chunk header) + 256×6 + 256×4 = **2568 bytes**  
- `reconstruct_and_encode_image`: 2+4+1+1 (video header) + mainChunkSize/8 = **8 + video_data bytes**  
Total: **2576 + video_data bytes** → overflows by **8 bytes**

**Actual written (first frame, max codebook):**  
- `roq_write_video_info_chunk`: **16 bytes** (not in formula at all)  
- codebook + video = 2568 + 8 + video_data  
Total: **2592 + video_data bytes** → overflows by **24 bytes**

---

## VULN: Heap Buffer Overflow in roq_encode_frame due to missing RoQ chunk headers in output packet size calculation
- **漏洞类别**: memory-safety
- **函数**: roq_encode_frame()
- **行号**: 1068-1097
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (transcoded to RoQ format)
- **外部触发路径**: `ffmpeg -i crafted.avi -c:v roqvideo output.roq` → `avcodec_encode_video2()` → `roq_encode_frame()` → `write_codebooks()` / `roq_write_video_info_chunk()` writes past end of `pkt->data` allocation
- **描述**: `roq_encode_frame` (line 1070) computes the output packet size as `((w*h/64)*138 + 7)/8 + 256*(6+4) + 8`. The formula accounts for: (a) max video-data bytes, (b) 2560 bytes of codebook entry data (256 CB2×6 + 256 CB4×4), (c) 8 bytes for the RoQ_QUAD_VQ video chunk header. However, it omits the 8-byte RoQ_QUAD_CODEBOOK chunk header written unconditionally (when numCB2>0) by `write_codebooks` (lines 614–617: two `bytestream_put_le16/le32/le_byte` calls = 2+4+1+1=8 bytes), and the 16-byte RoQ_INFO info chunk written on the first frame by `roq_write_video_info_chunk` (line 1087). Both `write_codebooks` and `reconstruct_and_encode_image` use the raw `enc->out_buf` pointer without bounds checking. When the total written data exceeds the allocated packet size, `enc->out_buf` marches past `pkt->data + size`, corrupting adjacent heap memory.
- **触发条件**: 攻击者提供一个包含大量不同像素值的输入视频文件（如 AVI/MP4），使得 RoQ 编码器使用大量 CB2 和 CB4 codebook 条目（非首帧：`numCB2×6 + numCB4×4 > 2552`；首帧：`> 2536`）。以 quake3_compat=1（默认）为例，当 numCB2≥253、numCB4=255 时首帧即可触发；非首帧需 numCB2≥253、numCB4≥255。对于 ≥64×64 的帧加精心设计的像素分布（覆盖所有 256 种 2×2 YUV 模式），该条件可被系统性地满足。
- **安全影响**: 最多 8 字节（非首帧）或 24 字节（首帧）的堆越界写入，写入内容为经编码的视频码流数据（type codes + codebook 索引 + motion vector 字节），受输入帧像素值影响、部分可由攻击者控制。堆元数据（如 glibc 的 size 字段）若紧邻分配区结尾，可被覆盖，最坏情况下可借助堆利用技术实现远程代码执行；最低限度造成崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
