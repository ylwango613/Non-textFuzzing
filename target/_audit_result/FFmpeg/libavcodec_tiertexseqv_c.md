I now have all the context I need. Let me do the final analysis.

**Key findings from the complete read:**

**`ff_log2_tab` (exact values):**
- Index 0→0, 1→0, 2→1, 3→1, 4→2, 5-6→2, 7→2, 8-15→3, …, 64-127→6, 128-255→7

**`seq_decode_op1` color_table OOB read (lines 112–120):**
- `len` = byte read from packet, range 1–127 (line 90, filtered at 110–111)
- `bits = ff_log2_tab[len-1] + 1` = floor(log2(len-1)) + 1 = ceil(log2(len)) roughly
- Bounds check at line 113 guarantees at least `len + 8*bits` bytes from `src`
- `color_table = src; src += len` → color_table has exactly `len` valid bytes
- Bit loop: `dst[i] = color_table[get_bits(&gb, bits)]` — `get_bits` returns [0, 2^bits − 1]

For **non-power-of-2 `len`** values, `2^bits − 1 ≥ len`, so `get_bits` can return an index ≥ len → OOB read past color_table.

Critical sub-case for **len ∈ [65, 71]** (bits=7, guaranteed bytes = len+56 < 128):
- `get_bits` can return 127 → `color_table[127]` = `*(src_original + 127)` 
- But `src_end − src_original` is only guaranteed to be `len + 56` (e.g. 121 for len=65)
- Reads up to **7 bytes past the declared packet boundary** (into the 64-byte AV_INPUT_BUFFER_PADDING_SIZE zero-pad region)

**`seqvideo_decode` missing initial bounds check (line 174):**
- `flags = *data++` with no check that `data_size >= 1` before dereferencing
- The standard SEQ demuxer always writes at least the 1-byte flags field (`pkt->data[0]`), so from the canonical path the minimum is 1 byte; but via fuzzing or alternative transports a 0-byte packet produces a NULL/past-end dereference

## VULN: seq_decode_op1 Out-of-Bounds Read via Non-Power-of-Two Color Table Length
- **漏洞类别**: memory-safety
- **函数**: seq_decode_op1()
- **行号**: 112-120
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted .seq media file
- **外部触发路径**: ffmpeg -i crafted.seq -f null - → avformat_open_input() → ff_tiertexseq_demuxer → seq_read_packet() → tiertexseqvideo decoder → seqvideo_decode_frame() → seqvideo_decode() → seq_decode_op1() → color_table[get_bits(&gb, bits)] OOB read
- **描述**: 在 `seq_decode_op1` 的 else 分支（line 109–126），从数据包读取 1 字节 `len`（范围 1–127），然后计算 `bits = ff_log2_tab[len-1] + 1`，这等于 ⌈log₂(len)⌉ 的近似值。该函数建立一个大小为 `len` 字节的调色表 `color_table`，并通过 `get_bits(&gb, bits)` 读取 bits 位的调色板索引（值域 [0, 2^bits − 1]）。当 `len` 不是 2 的幂时，`2^bits − 1 ≥ len`，`get_bits` 可以返回大于等于 `len` 的索引，造成 `color_table[index]` 越界读取。第 113 行的边界检查仅保证至少 `len + 8*bits` 字节可用。对于 len ∈ [65, 71]（此时 bits=7），保证字节数为 len+56 ∈ [121, 127]，而最大索引为 127，因此 `color_table[127]` 可读取超出数据包声明大小之外最多 7 字节的内存（落入 AV_INPUT_BUFFER_PADDING_SIZE 的零填充区域）。越界读取的字节随后被写入视频帧缓冲区 `dst[i]`。
- **触发条件**: 攻击者构造一个 .seq 文件，使某一视频帧的 op1 数据块中的 `len` 字节为非 2 的幂值（如 3、5、6、7、9–15、65–71 等），并在后续比特流中设置大于等于 `len` 的调色板索引位图案。FFmpeg 以 `ffmpeg -i crafted.seq -f null -` 或任意消费 SEQ 文件的 API 调用即可触发。
- **安全影响**: OOB 读取的字节（对于 len∈[65,71] 读取的是零填充区域；对于其他非 2 的幂 len 读取的是数据包内紧邻字节流数据）被写入输出视频帧，可能造成轻微信息泄露（帧输出中混入数据包字节）以及视频渲染错误。在极端内存布局下，越界访问可能触发进程崩溃（DoS）。

## VULN: seqvideo_decode Missing Initial Packet Size Check Leading to OOB Read
- **漏洞类别**: memory-safety
- **函数**: seqvideo_decode()
- **行号**: 165-174
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file (zero-size video packet)
- **外部触发路径**: ffmpeg -i crafted.seq -f null - → avformat_open_input() → ff_tiertexseq_demuxer → seqvideo_decode_frame() → seqvideo_decode(seq, buf=NULL/empty, buf_size=0) → flags = *data++ (OOB read / NULL deref)
- **描述**: `seqvideo_decode` 函数（line 165）在读取第一个字节 `flags = *data++`（line 174）之前没有检查 `data_size >= 1`。若 `avpkt->size == 0`，则 `data_end = data + 0 = data`，指针 `data` 指向零长度缓冲区末尾，`*data` 造成越界读取；若 `avpkt->data == NULL`（空包），则触发空指针解引用，引发进程崩溃（SIGSEGV）。`seqvideo_decode_frame` 在调用 `seqvideo_decode` 前没有对 `buf_size` 做任何最小大小校验。
- **触发条件**: 向 tiertexseqvideo 解码器提供一个 `avpkt->size == 0` 的零长度视频数据包。标准 SEQ 解复用器始终会写入至少 1 字节（flags 字节），但在模糊测试、自定义 AVPacket 注入或将该解码器与其他容器格式配合使用时，可直接提供空包触发该路径。
- **安全影响**: 进程崩溃（DoS）。在极端内存布局下，OOB 读取的字节若被后续代码使用（如 `flags & 1` / `flags & 2` 分支判断）可能造成不可预期的控制流，但主要影响为可靠崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
