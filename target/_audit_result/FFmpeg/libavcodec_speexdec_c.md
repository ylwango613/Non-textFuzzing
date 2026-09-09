The `bytestream_get_le32` at line 43–46 is a raw memory read with no bounds check. This confirms the OOB read in `parse_speex_extradata`.

**Batch 1 findings (lines 1–600):** No write OOBs found. `split_cb_shape_sign_unquant` uses hardcoded `nb_subvect ≤ 8`, always within `signs[10]`/`ind[10]`.

**Batch 2 findings (lines 600–1200):** `inner_prod` loops in steps of 8 and always accesses `x[i+7]` — but every call site uses `len = 80` (multiple of 8). No exploitable OOB. `sb_decode`'s `float exc[80]` matches `subframe_size ≤ 80`. No write OOBs.

**Batch 3 findings (lines 1200–1604):**

`parse_speex_extradata` (lines 1401–1441): `av_strnstr` can return a pointer at offset P > 0 within extradata. After `buf += 28`, ten `bytestream_get_le32` + one `buf += 4` advance consume **44 bytes total** (reads extradata[P+28 .. P+71]). The only guard is `extradata_size >= 80`, but NOT that P+71 < extradata_size. An attacker placing `"Speex   "` at offset ≥ 9 in an 80-byte extradata triggers a heap OOB read — confirmed unbounded by the `DEF()` macro above.

`speex_decode_stereo` in-place expansion and `qmf_synth` buffers are within bounds for all supported modes. No additional write OOBs.

---

## VULN: Heap OOB Read in parse_speex_extradata via Misplaced "Speex   " Marker
- **漏洞类别**: memory-safety
- **函数**: parse_speex_extradata()
- **行号**: 1405-1438
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (Matroska, MP4, or any container providing Speex codec-private/extradata)
- **外部触发路径**: ffmpeg -i crafted.mkv -f null - → avformat_open_input() → matroska_read_header() [sets avctx->extradata to attacker-controlled CodecPrivate bytes] → avcodec_open2() → speex_decode_init() → parse_speex_extradata()
- **描述**: `parse_speex_extradata()` calls `av_strnstr(extradata, "Speex   ", extradata_size)` to locate the Speex magic string at an arbitrary byte offset P within the extradata buffer. After advancing `buf += 28`, the function performs ten sequential `bytestream_get_le32(&buf)` calls plus one `buf += 4` skip, consuming 44 unbounded bytes (reads `extradata[P+28 .. P+71]`). The only guard is `avctx->extradata_size >= 80` (line 1452), which ensures the total buffer is at least 80 bytes but does NOT prevent reading past the buffer end when P ≥ 9: the last `bytestream_get_le32` accesses `extradata[P+68 .. P+71]`, which exceeds the 80-byte buffer by up to (P+71−79) bytes. Since `bytestream_get_le32` is an unchecked raw memory read (via the `DEF()` macro in `bytestream.h`), this directly dereferences heap memory beyond the allocation.
- **触发条件**: 攻击者构造一个包含 Speex 音频流的 Matroska (.mkv)、MP4 或其他支持任意 codec private data 的容器，将 `CodecPrivate` 字段设置为至少 80 字节的缓冲区，但将 `"Speex   "` 标记放在偏移量 ≥ 9 处（例如：前 9 字节为任意填充，之后跟 `"Speex   "` + 只有 63 字节有效数据，总计 80 字节）。当 FFmpeg 用 `-i crafted.mkv -f null -` 打开文件时，demuxer 将 CodecPrivate 设为 `avctx->extradata`，触发 `parse_speex_extradata` 中的越界读取。
- **安全影响**: 堆越界读取 — 最坏情况：读取解码器初始化时相邻的堆元数据或其他堆对象内容，可能造成敏感内存信息泄露（地址、密钥材料）。在某些内存布局下可能导致程序崩溃（DoS）。虽无直接写原语，但结合其他信息泄露可辅助 ASLR 绕过。

<!-- AUDIT_PROMPT_VERSION: 1 -->
