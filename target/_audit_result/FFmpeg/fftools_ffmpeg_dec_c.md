I have completed the full analysis of the 1795-line file. Let me compile the final findings.

**Analysis summary by section:**

- **Lines 1-500 (dec_alloc, audio/video processing)**: No memory allocation issues; all sizes use internal struct sizes or well-bounded frame fields.
- **Lines 448-527 (copy_av_subtitle)**: `src_rect->h * src_rect->linesize[j]` — both `int` — assigned to `size_t buf_size` with **no overflow check**. Integer overflow produces an underallocated heap buffer; `dst_rect->linesize[j]` is then set to the original large value, so downstream bitmap rendering reads/writes beyond the allocation.
- **Lines 1643-1650 (dec_open subtitle_header)**: `subtitle_header_size + 1` as `int` arithmetic — if `subtitle_header_size == INT_MAX`, result wraps. But because `avcodec_open2()` validates sizes before setting `subtitle_header`, the reachable maximum is bounded by available memory and not practically exploitable to INT_MAX.
- **Lines 1087-1302 (multiview_setup)**: `view_map` array indexing protected by `vs->val >= nb_view_ids_av` bounds check before array access; `nb_view_ids_av` capped at `sizeof(views_wanted)*8`. Safe.
- **Remaining sections**: scheduler interactions, hw device setup, decoder threading — no identified memory safety issues.

## VULN: copy_av_subtitle signed-int overflow leads to heap underallocation and OOB read/write
- **漏洞类别**: memory-safety
- **函数**: copy_av_subtitle()
- **行号**: 503-514
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (MKV/MPEG-TS with malicious bitmap subtitle track)
- **外部触发路径**: `ffmpeg -i <crafted.mkv> -f null -` → `avformat_open_input()` → demuxer reads bitmap subtitle track → `avcodec_decode_subtitle2()` → decoded `AVSubtitleRect` with attacker-controlled `h`/`linesize[j]` → `transcode_subtitles()` → `process_subtitle()` → `fix_sub_duration_heartbeat()` → `subtitle_wrap_frame(dp->sub_heartbeat, prev_subtitle, 1)` → `copy_av_subtitle(sub, subtitle)` → integer overflow in `buf_size` computation → `av_memdup` underallocates → downstream OOB
- **描述**: 在 `copy_av_subtitle()` 的第 503–505 行，`buf_size` 通过 `src_rect->h * src_rect->linesize[j]` 计算，其中 `h` 和 `linesize[j]` 均为 `int` 类型（见 `avcodec.h:2075,2083`）。两个 `int` 相乘的结果依然是 `int`，当乘积超过 `INT_MAX` 时发生有符号整数溢出（UB，实际在 x86/x86-64 上 wraparound）。例如：`h = 65537`, `linesize[j] = 65536` → 乘积 = `4295032832` → 32-bit 截断后 = `65536`，隐式转换为 `size_t buf_size = 65536`。随后 `av_memdup(src_rect->data[j], 65536)` 仅分配 65536 字节，但第 514 行 `dst_rect->linesize[j] = src_rect->linesize[j]`（= 65536）和 `dst_rect->h`（= 65537）均保留原值。下游使用 `h * linesize` 遍历位图数据时，会越界访问远超分配大小的堆内存（实际访问 65537 × 65536 ≈ 4 GB 数据，但缓冲区仅 65536 字节）。
- **触发条件**: 构造一个包含 bitmap subtitle track（DVB-Sub、VobSub 等）的 MKV 或 MPEG-TS 文件，使解码后的 `AVSubtitleRect` 中 `h` 和 `linesize[j]` 的乘积发生 32-bit signed 整数溢出至较小正值（如 `h=65537, linesize=65536`）。该字幕字轨需启用 `DECODER_FLAG_FIX_SUB_DURATION`（fix_sub_duration），使 `fix_sub_duration_heartbeat` 触发 `copy=1` 的 `subtitle_wrap_frame` 分支，进而调用 `copy_av_subtitle`。
- **安全影响**: 越界写（当下游 subtitle 渲染器向 `dst_rect->data[j]` 写像素数据时）或越界读（读取相邻堆块数据），可被利用实现任意代码执行（RCE）或信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
