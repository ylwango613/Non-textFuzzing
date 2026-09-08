I now have sufficient context to complete the analysis. Let me summarize the complete audit findings.

**Audit complete.** Here is my detailed analysis result:

**File:** `libavcodec/bsf/aac_adtstoasc.c` (157 lines — small, read in one pass)

**Key code path traced:**
- `aac_adtstoasc_filter` → PCE path (lines 80–96)
- `init_get_bits(&gb, pkt->data, pkt->size * 8)` then `ff_copy_pce_data(&pb, &gb)`
- `get_bits_count(&gb)` after safe-reader cap = at most `pkt->size * 8 + 8`
- Integer division: `(pkt->size * 8 + 8) / 8 = pkt->size + 1`
- `pkt->size -= (pkt->size + 1)` → `pkt->size = -1`, returned as success

**Items confirmed NOT vulnerable:**
- `pce_data[MAX_PCE_SIZE]` (320 bytes) stack buffer: max PCE payload ≈ 305 bytes, no overflow
- `memcpy(extradata + 2, pce_data, pce_size)`: allocation exactly sized, pce_size ≤ 305
- `flush_put_bits` `av_assert0`: not triggered since pce_data is never filled to capacity

---

## VULN: pkt->size integer underflow via oversized PCE comment field
- **漏洞类别**: memory-safety
- **函数**: aac_adtstoasc_filter()
- **行号**: 82-95
- **CWE**: CWE-191 (Integer Underflow)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted AAC/ADTS media file
- **外部触发路径**: `ffmpeg -i malicious.aac -acodec copy out.mp4` → `av_bsf_receive_packet()` → `aac_adtstoasc_filter()` → `ff_copy_pce_data(&pb, &gb)` → `pkt->size -= get_bits_count(&gb)/8` (line 94)
- **描述**: 在 PCE 路径（`hdr.chan_config == 0`）中，`init_get_bits` 以 `pkt->size * 8` 位初始化 GetBitContext。在 CONFIG_SAFE_BITSTREAM_READER=1（FFmpeg 默认）下，`SKIP_COUNTER` 宏将内部索引上限限制为 `size_in_bits_plus8 = pkt->size * 8 + 8`，即 `get_bits_count(&gb)` 最大为 `pkt->size * 8 + 8`，整除后为 `pkt->size + 1`。第 94 行执行 `pkt->size -= get_bits_count(&gb)/8`，当 PCE 的 `comment_size` 字段（8 位值，最大 255）声明的字节数超过包中剩余数据时，安全读取器会继续计数（但返回 0 值），使索引达到上限，最终导致 `pkt->size -= (pkt->size + 1)`，即 `pkt->size = -1`。该函数在第 120 行返回 0（success），将 `size = -1` 的损坏包传递给下游处理器。若下游代码（如 muxer 的 `avio_write` 或 `av_grow_packet`）将 `pkt->size` 隐式转换为无符号类型用于 malloc/memcpy，则 `-1` 变为 `SIZE_MAX`，导致堆申请失败或巨型 OOB 读取。
- **触发条件**: 构造一个 chan_config=0 的 ADTS 帧：ADTS 头之后紧跟有效的 PCE 语法元素（前 3 位 = 5），PCE 中的 `comment_size` 字节（在 `align_put_bits` 对齐之后）设为 0xFF（255），但实际包负载仅有少量字节（如 10 字节），导致安全读取器的循环计数超出缓冲区上限，令 `get_bits_count/8 = pkt->size + 1`。
- **安全影响**: 短期：向下游（muxer/decoder）传递 `pkt->size = -1` 的损坏数据包，若下游代码以无符号方式使用该尺寸（如 `(size_t)pkt->size` = `SIZE_MAX`），触发进程崩溃（DoS）；若某路径将此无符号大值作为 `malloc/realloc` 的参数，可能触发内存分配失败或条件满足时的越界读取，为潜在信息泄露打开窗口。

<!-- AUDIT_PROMPT_VERSION: 1 -->
