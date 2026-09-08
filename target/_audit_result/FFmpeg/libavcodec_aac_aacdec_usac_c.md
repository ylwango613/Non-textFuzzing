I've completed a thorough multi-pass read of the entire 2208-line file plus key headers. Here is my analysis:

**Batch 1 (L1-450):** `decode_loudness_set` reads `nb_album`/`nb_info` from 6 bits (max 63) and indexes into `album_info[64]`/`info[64]` — bounded, safe. v1 path has an explicit bounds check. `decode_usac_extension` and config parsing paths look clean.

**Batch 2 (L450-900):** `ff_aac_usac_config_decode` — `nb_elems` validated ≤ 64 before looping into `elems[64]`. `layout_map` access bounded by `nb_channels ≤ 64`. `decode_spectrum_ac` — `coef[2*i+0/1]` where `i < len/2`, `len` passed as `ics->swb_offset[max_sfb] ≤ N ≤ 1024`. Safe.

**Batch 3 (L900-1350):** `decode_usac_stereo_cplx` — all accesses into `pred_used[128]`, `alpha_q_re[1024]` use `g*max_sfb_ste + sfb`; maximum index (8 groups × 15 sfb) = 119 < 128. `sfo[128]`/`sf[128]` similarly safe. `decode_usac_stereo_info` properly calls `setup_sce` (which validates `max_sfb ≤ num_swb`) before using `max_sfb_ste`.

**Batch 4 (L1350-1730):** `smg_data[9][28]` accessed with `i ≤ 7, j ≤ 13`. `tsd_phase_data[64]` with `i < nb_time_slots ≤ 64`. All safe.

**Batch 5 (L1730-2208):** **Found the key vulnerability in `parse_ext_ele`**:

At L1994-2013, `e->ext.pl_data_offset` (uint32_t) accumulates `len` (uint32_t) across fragmented frames. If `pl_data_offset + len` wraps, the allocation is tiny but `memcpy` uses the pre-wrap count → heap overflow. Also verified: `parse_audio_preroll` — `tmp_buf_size` not updated after realloc is a logic bug but not exploitable (buffer is `au_len*8` bytes, writes `au_len` bytes).

## VULN: Integer Overflow in pl_data_offset Causes Heap Buffer Overflow in parse_ext_ele
- **漏洞类别**: memory-safety
- **函数**: parse_ext_ele()
- **行号**: 1993-2013
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (USAC/AAC bitstream with fragmented extension elements)
- **外部触发路径**: ffmpeg -i <crafted_usac_file> -f null - → avformat_open_input() → ff_aac_usac_decode_frame() → parse_ext_ele() → integer overflow at `e->ext.pl_data_offset + len` → av_refstruct_alloc_ext() underallocates → memcpy OOB write
- **描述**: In `parse_ext_ele()`, when a USAC extension element is configured with `payload_frag=1` (set via `decode_usac_extension()` from the container's bitstream), the per-frame payloads can be accumulated across frames by keeping `pl_frag_start=0, pl_frag_end=0`. The accumulator `e->ext.pl_data_offset` is `uint32_t`; `len` is also `uint32_t` (max ~65788 per frame). After approximately 65,278 frames, the addition `e->ext.pl_data_offset + len` overflows `uint32_t` and wraps to a small value before being implicitly widened to `size_t` for the `av_refstruct_alloc_ext()` call. This allocates a tiny buffer (possibly as small as 0 bytes + refcount overhead) while the subsequent `memcpy(tmp_buf, e->ext.pl_buf, e->ext.pl_data_offset)` uses the pre-wrapped (huge) value of `pl_data_offset` as the copy length, writing far beyond the bounds of the newly allocated heap buffer.
- **触发条件**: 攻击者需构造一个含 USAC 音频的媒体文件（如 MP4/AAC），其中：(1) 扩展元素配置中 `usacExtElementPayloadFrag=1`；(2) 在后续约 65,000+ 帧中持续设置 `usacExtElementStart=0, usacExtElementStop=0`（片段延续）且每帧 `len≈65788` 字节。在 `pl_data_offset` 累积至接近 UINT32_MAX 后，再一帧触发整数溢出并引发 memcpy 堆溢出。需要系统具备数 GB 空闲内存以支撑中间阶段的缓冲区增长（约 4GB 峰值）。
- **安全影响**: 最坏情况下可实现远程代码执行（RCE）：攻击者通过精心控制溢出写入的内容（利用 jemalloc/ptmalloc 堆布局）可覆盖相邻堆元数据或函数指针，最终劫持控制流。在大多数实际环境中，首先触发进程 OOM 崩溃（DoS）；但在高内存服务器场景（媒体处理服务）中存在可利用为 RCE 的风险。

<!-- AUDIT_PROMPT_VERSION: 1 -->
