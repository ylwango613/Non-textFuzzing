**分析完了。** ファイル全体を精読した結果:

**`cbs_jpeg_syntax_template.c` 内の各関数の評価:**
- `frame_header`: `Nf` は [1,255] に厳密バリデート済み、配列サイズ 255 → 安全
- `dqt`: `n = Lq/65`、最大 `262/65=4`、配列サイズちょうど 4 → 安全（`ff_cbs_read_unsigned` は範囲外で `AVERROR_INVALIDDATA` を返す）
- `dht`: `i >= 8` ガード → 安全
- `huffman_table`: `FF_ARRAY_ELEMS(current->V)` チェック → 安全
- `application_data`/`comment`: `Lp-2`/`Lc-2` バイト確保して `Lp-2`/`Lc-2` 回ループ → 安全

**関連ファイル `cbs_jpeg.c` で発見された OOB Read（line 163）:**

`length > frag->data_size - i` チェックは `length == frag->data_size - start`（つまり `end == frag->data_size`）を許可してしまい、その直後 `frag->data[end]` = `frag->data[frag->data_size]` を読む — 1 バイト OOB Read。

---

## VULN: Off-by-One OOB Read in cbs_jpeg_split_fragment Non-SOS Marker Processing
- **漏洞类别**: memory-safety
- **函数**: cbs_jpeg_split_fragment()
- **行号**: 155-163 (cbs_jpeg.c)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted JPEG media file
- **外部触发路径**: ffmpeg -i <crafted.jpg> -f null - → avformat_open_input() → ff_cbs_read() → cbs_jpeg_split_fragment() → cbs_jpeg_split_fragment() non-SOS branch (line 155-163)
- **描述**: 在 `cbs_jpeg_split_fragment`（`cbs_jpeg.c`）处理非 SOS 标记段时，第 155 行的边界检查为 `length > frag->data_size - i`（`i == start`），允许 `length == frag->data_size - start` 通过校验。此时 `end = start + length == frag->data_size`，第 163 行随即执行 `frag->data[end]`（即 `frag->data[frag->data_size]`），触发 1 字节的堆越界读取。正确的校验应为 `length >= frag->data_size - i`（使用 `>=` 而非 `>`）。
- **触发条件**: 攻击者构造一个畸形 JPEG 文件，使某个非 SOS 标记（如 APP、DQT、DHT、COM）的 16 位长度字段恰好等于该字段在缓冲区内到末尾的剩余字节数，即令 `Lx == frag->data_size - start`。
- **安全影响**: 在典型 FFmpeg 路径中，`AVPacket` 数据末尾存在 `AV_INPUT_BUFFER_PADDING_SIZE`（64 字节）填充，越界读一个填充字节（值为 0x00），不触发崩溃，但会错误地将 `next_marker` 设为 -1 导致解析提前终止。若通过非标准路径（如手动构造 `CodedBitstreamFragment` 无填充）调用 CBS，则可能触发堆越界读崩溃（DoS）或泄露 1 字节相邻堆内存（信息泄露）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
