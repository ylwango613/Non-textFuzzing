I have completed the full analysis. Let me trace the exact off-by-one OOB write I found before writing the report:

- **`g722_encode_frame` (line 351)**: `out_size = (frame->nb_samples + 1) / 2` → allocates `out_size` bytes (valid: indices 0 … out_size−1).
- When `frame->nb_samples` is even: `nb_samples = frame->nb_samples`, `out_size = nb_samples / 2`.
- **`g722_encode_trellis` outer loop** runs `i` from 0 to `nb_samples/2 − 1`, exits with `i = nb_samples/2`.
- **Final backtracking block (line 313)**: `for (j = i; j > froze; j--)` → first write is `dst[nb_samples/2]` = `dst[out_size]` — exactly 1 byte past the allocated packet buffer.
- With the default frame size of 320 (even), every trellis-encoded G.722 frame triggers this write.

---

## VULN: Off-by-one OOB write in g722_encode_trellis final backtracking loop
- **漏洞类别**: memory-safety
- **函数**: g722_encode_trellis()
- **行号**: 311-317
- **CWE**: CWE-193 (Off-by-one Error)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file / application using FFmpeg G.722 encoder with trellis enabled
- **外部触发路径**: `ffmpeg -i <file> -c:a g722 -trellis 1 output.wav` → `avcodec_send_frame()` → `g722_encode_frame()` → `g722_encode_trellis()` → final backtracking loop writes `dst[nb_samples/2]` (= `dst[out_size]`), one byte past the end of the `avpkt->data` heap buffer
- **描述**: 在 `g722_encode_frame`（第 351 行）中，输出缓冲区以 `out_size = (frame->nb_samples + 1) / 2` 字节分配。当 `frame->nb_samples` 为偶数时，`nb_samples == frame->nb_samples`，`out_size = nb_samples / 2`，缓冲区合法下标为 `0 .. out_size-1`。`g722_encode_trellis` 的外层循环（第 189 行）运行 `i` 从 0 到 `nb_samples/2 − 1`，退出时 `i = nb_samples/2`。随后的最终回溯块（第 313 行）执行 `for (j = i; j > froze; j--) dst[j] = ...`，第一次迭代即写入 `dst[nb_samples/2] = dst[out_size]`，超出堆分配缓冲区 1 字节，造成单字节堆越界写入（off-by-one heap OOB write）。默认帧大小为 320（偶数），因此只要启用 trellis（`-trellis N`，N≥1），每帧编码必然触发此越界写入。
- **触发条件**: 使用 FFmpeg G.722 编码器时，设置 trellis 参数（`-trellis 1` 至 `-trellis 16`）且输入音频帧的样本数为偶数（默认 320）。攻击者通过构造能迫使目标应用使用 G.722 trellis 编码的媒体文件或输入流即可触发，无需特殊文件格式。
- **安全影响**: 单字节堆越界写入，写入值为合法 G.722 码字（0–255），恰好覆盖 `avpkt->data` 后紧邻的堆元数据或其他对象。在 ptmalloc/jemalloc 等常见堆实现下，可通过精心构造的帧序列实现堆元数据污染，最坏情况下导致任意代码执行（RCE）；可靠情况下至少引发堆损坏崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
