I now have enough context to form a complete analysis. Let me trace the key vulnerability path:

**In `stats()` (line 34-50):** `sum` is `unsigned` (32-bit). It accumulates `in[n]->size` (cast from `int`). With multiple large invisible frames, `sum` can silently wrap to near 0 with no overflow check.

**In `merge_superframe()` (line 61):** `sz = sum + 2 + (mag + 1) * n_in` inherits the wrapped `sum`. `av_new_packet(out, sz)` takes `int size` (packet_alloc rejects negative values and values ≥ `INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE`). When `sz` wraps to a small positive value (e.g., 34 bytes), `av_new_packet` succeeds with a tiny allocation.

**memcpy loop (lines 66-69):** Iterates with the original large `in[n]->size` values, writing far beyond the tiny allocated buffer → heap overflow.

**Concrete scenario:** Two invisible VP9 frames each exactly 2 GB → `sum = 2^32 → wraps to 0 → sz ≈ 34 bytes` → `av_new_packet` allocates 34 bytes → `memcpy` writes 4 GB → massive heap overflow.

## VULN: Integer Overflow in stats() Leading to Heap Buffer Overflow in merge_superframe()
- **漏洞类别**: memory-safety
- **函数**: stats() / merge_superframe()
- **行号**: 38-48 (stats), 54-99 (merge_superframe)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted VP9 media file (webm/matroska) with multiple large invisible alt-ref frames
- **外部触发路径**: `ffmpeg -i malicious.webm -bsf:v vp9_superframe output.mp4` → `vp9_superframe_filter()` → `ff_bsf_get_packet_ref()` [repeated for each invisible frame, caching up to 8 in s->cache] → `merge_superframe(s->cache, s->n_cache, pkt)` → `stats(in, n_in, &max, &sum)` [sum wraps at line 45] → `sz = sum + 2 + (mag+1)*n_in` [tiny value] → `av_new_packet(out, sz)` [tiny heap allocation] → `memcpy(ptr, in[n]->data, in[n]->size)` [loop writes original large sizes → heap OOB write]
- **描述**: 在 `stats()` 中，`sum` 被声明为 `unsigned`（32位），在无溢出检查的情况下累加每个 `AVPacket->size`（从 `int` 隐式转换为 `unsigned`）。当所有缓存帧的总大小超过 `UINT32_MAX`（4 GB）时，`sum` 发生无符号整数回绕，变为一个很小的值（如 0）。`merge_superframe()` 中的 `sz = sum + 2 + (mag + 1) * n_in` 继承这个回绕后的极小值，导致 `av_new_packet(out, sz)` 仅分配数十字节的堆缓冲区。随后的 `memcpy` 循环（第 66–69 行）仍以各帧原始的大 `in[n]->size`（总计数 GB）为长度向该极小缓冲区写入数据，造成大规模堆溢出。
- **触发条件**: 攻击者构造一个 webm/matroska 容器文件，其中包含 2 个或更多 VP9 不可见（invisible/alt-ref）帧，且这些帧的大小之和超过 4 GB（例如：2 个各为 2 GB 的不可见帧）。每帧开头只需前几字节构成合法的 VP9 帧头（将 show_existing_frame 位置 0、keyframe 位置 0、show_frame 位置 0 以将 invisible 设为 1），其余内容可任意填充。由于 `vp9_superframe_filter()` 对帧数据大小无上界限制（仅检查非零），demuxer 会将这些超大帧数据读入 `AVPacket` 并逐个缓存，最终触发 `merge_superframe()` 的整数溢出路径。
- **安全影响**: 堆越界写（写入量达数 GB），可覆盖紧邻堆元数据及任意堆对象，在有经验的攻击者手中可导致任意代码执行（RCE）。最坏情况为远程代码执行（用户通过 ffmpeg 处理网络传输的恶意媒体文件时）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
