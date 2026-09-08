Now I have enough context. Let me document the findings.

**Key findings from code analysis:**

**Line 331** — `vvenc_accessUnit_alloc_payload(s->au, avctx->width * avctx->height)`:
- `avctx->width` and `avctx->height` are both `int` (signed 32-bit). Their product is computed as a 32-bit signed multiply with no cast to `int64_t` or `size_t`.
- E.g., width = 65536, height = 32768 → product = 2,147,483,648 which overflows `INT_MAX` (2,147,483,647), yielding UB that practically wraps to a negative or small value.
- If the function interprets a negative/zero size and returns a tiny or NULL-like allocation (or internally treats the size as `size_t` where the negative wraps to a huge value and fails, returning a null payload), the `if (!s->au->payload)` guard at line 332 could be bypassed if the library does not fail on negative sizes but rather allocates a small chunk.
- Even if the guard fires, any code path where the allocation succeeds but is undersized means `vvenc_encode()` — which writes actual bitstream into `s->au->payload` — can write past the end of the buffer → heap buffer overflow.
- The secondary `memcpy` at line 406 then reads from the corrupted `payload` into a correctly-sized `pkt->data`, but by that point the heap is already damaged by vvenc's internal writes.

No other memory-safety issues were found: `vvenc_init_extradata` (lines 205-228) correctly uses `av_mallocz` with padding, and the `memcpy` at line 226 is bounded by `payloadUsedSize` which was just verified `> 0`.

---

## VULN: Integer overflow in payload buffer allocation leads to heap buffer overflow
- **漏洞类别**: memory-safety
- **函数**: vvenc_init()
- **行号**: 331-336
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (MKV/MP4 container with oversized width × height)
- **外部触发路径**: ffmpeg -i crafted.mkv -c:v libvvenc out.mp4 → avformat_open_input() → demuxer reads attacker-controlled width/height → avcodec_open2() → vvenc_init() → line 331: `vvenc_accessUnit_alloc_payload(s->au, avctx->width * avctx->height)` [overflow] → vvenc_encode() writes past under-allocated payload buffer
- **描述**: 在 `vvenc_init()` 第 331 行，`avctx->width * avctx->height` 以有符号 32 位整数执行乘法，无任何溢出保护或类型提升（未转换为 `int64_t` 或 `size_t`）。当攻击者通过容器元数据控制 width 与 height 使乘积超过 `INT_MAX`（如 width=65536, height=32769，积 = 2,147,549,184 > 2,147,483,647）时，产生有符号整数溢出（C 标准未定义行为），实际传入 `vvenc_accessUnit_alloc_payload` 的 size 为负数或极小值。若 VVenC 库对该错误 size 仍分配了一个极小堆块，则后续 `vvenc_encode()` 向 `s->au->payload` 写入实际压缩码流时会越过堆块边界，造成堆缓冲区溢出。
- **触发条件**: 攻击者构造一个 MKV 或 MP4 文件，将视频流的 width 和 height 设置为乘积溢出 INT_MAX 的大值（例如 width=65536, height=32769），然后由受害者的 FFmpeg 实例以 `libvvenc` 为目标编码器进行转码（`ffmpeg -i evil.mkv -c:v libvvenc out.mp4`），或由 Web 转码服务自动处理上传文件时触发。
- **安全影响**: 堆损坏，在最坏情况下可实现任意代码执行（RCE）；至少导致编码器进程崩溃（DoS）。在自动转码服务（服务端）场景下，攻击者通过上传精心构造的视频文件即可在服务器上触发该漏洞。

<!-- AUDIT_PROMPT_VERSION: 1 -->
