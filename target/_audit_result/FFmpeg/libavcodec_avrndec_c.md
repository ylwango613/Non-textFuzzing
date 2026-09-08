The file is small (100 lines). I now have full context to assess it. Let me trace the critical arithmetic in the interlaced decode path precisely.

**Analysis of `decode_frame()` interlace path (lines 71–77):**

The size guard (line 63) accepts `buf_size >= 2 * avctx->width * avctx->height`.

`true_height = buf_size / (2 * avctx->width)` — integer floor division.

After `buf += (true_height - avctx->height) * avctx->width`, the loop's **second** `memcpy` (line 75) reads from:

```
buf + avctx->width * true_height + 4
```

Absolute offset from `avpkt->data` in iteration `j` (y = 2j):

```
(true_height - avctx->height)*W + j*2W + W*true_height + 4
= W*(2*true_height - avctx->height + 2j) + 4
```

In the **last iteration** for even `avctx->height` (j_max = avctx->height/2 − 1), this memcpy ends at:

```
W*(2*true_height - avctx->height + (avctx->height - 2) + 2) + 4 + 2W
= 2*W*true_height + 4
```

Since `buf_size = 2*W*true_height + R` (where 0 ≤ R < 2W), the end offset is `buf_size − R + 4`.

**When R < 4 (e.g., R=0 when buf_size is exactly divisible by 2W), this reads 1–4 bytes past the buffer.**

Concrete proof: width=100, height=4, buf_size=800 (minimum accepted by the size check).
- true_height = 4, buf advances by 0.
- y=2 (last iteration): second memcpy reads offsets 604–803, but buf_size=800 → bytes 800–803 are **out-of-bounds**.

The OOB bytes are then copied into `p->data[0]` (the output frame), leaking adjacent heap content.

---

## VULN: OOB Heap Read in AVRN Interlaced Decode Path
- **漏洞类别**: memory-safety
- **函数**: decode_frame()
- **行号**: 71-77
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file (AVI/Avid container with AVRN codec)
- **外部触发路径**: `ffmpeg -i <crafted.avi> -f null -` → `avformat_open_input()` → `avcodec_open2()` → `init()` (sets a->interlace=1 via extradata) → per-packet `avcodec_send_packet()` → `decode_frame()` → interlaced memcpy at line 75
- **描述**: `decode_frame()` 在 interlaced 路径中，第二个字段的 `memcpy` 源地址为 `buf + avctx->width * true_height + 4`（line 75）。其中 `+4` 是为了跳过第二场开头的 4 字节头部。但 line 63 的大小校验仅要求 `buf_size >= 2 * avctx->width * avctx->height`，而实际读取第二场最后一行所需的数据末尾为 `2 * avctx->width * true_height + 4` 字节。当 `buf_size` 恰好等于 `2 * avctx->width * avctx->height`（即 `true_height == avctx->height`，余数 R=0）时，最后一次迭代的 `memcpy` 会从 packet 缓冲区末尾之后读取最多 4 字节，构成堆越界读；读出的字节随即被写入输出帧 `p->data[0]`，造成堆内存内容泄漏。
- **触发条件**: 构造包含 AVRN codec 的 AVI 文件：①extradata 字段起始 5 字节设计使得 `extradata[4]+4+0..3 = "1:1("` 以开启 interlace 模式；②视频高度为正偶数（如 4）；③每帧 packet 大小精确等于 `2 * width * height`（最小合法值，且能被 `2*width` 整除使余数 R=0）。满足上述条件可使最后一次循环迭代的第二场 `memcpy` 越界读 4 字节。
- **安全影响**: 越界读取的 4 字节堆内存内容（可能含指针、密钥等敏感数据）被拷贝进解码后的视频帧数据，攻击者可通过读取帧输出实现**堆信息泄漏（heap info-leak）**，辅助 ASLR 绕过；若越界地址跨越内存页边界，也可触发进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
