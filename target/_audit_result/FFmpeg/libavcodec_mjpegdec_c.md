The vulnerability is confirmed. The root cause is clear:

- **SOF** (line 809-819): allocates `blocks[i]` with `size = bw * bh * h_count[i] * v_count[i]` where `bw = (width + h_max*8-1)/(h_max*8)`.
- **SOS** non-interleaved path (line 1754-1757): `h = h_max / h_scount[0]` — **integer (floor) division** — then `mb_width = (width + h*8-1)/(h*8)`.
- When `h_max` is not evenly divisible by `h_count[c]` (e.g. h_max=3, h_count[c]=2 → h=1), `mb_width ≈ 3×bw`, but blocks only has `bw * h_count[c]` entries per row.
- Scan loops (lines 1547-1549 DC path; lines 1614-1617 AC path) then walk `mb_width` columns and write into `blocks[c][block_idx]` far beyond the allocated size.

Concrete proof: width=72, h_max=3, h_count[c]=2, height=8 → bw=3, size=6, but max block_idx=8.

## VULN: Progressive JPEG blocks[] Heap OOB Write via Non-Divisible Sampling Factors
- **漏洞类别**: memory-safety
- **函数**: `ff_mjpeg_decode_sos()` / `mjpeg_decode_scan()` / `mjpeg_decode_scan_progressive_ac()`
- **行号**: 1754-1757 (OOB根因), 1547-1549 / 1614-1617 (OOB触发点), 809-819 (欠分配点)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (progressive JPEG with non-standard subsampling factors)
- **外部触发路径**: `ffmpeg -i crafted.jpg -f null -` → `ff_mjpeg_decode_frame()` → `ff_mjpeg_decode_frame_from_buf()` → `ff_mjpeg_decode_sof()` [欠分配 blocks[]] → `ff_mjpeg_decode_sos()` [计算过大 mb_width] → `mjpeg_decode_scan()` 或 `mjpeg_decode_scan_progressive_ac()` [OOB写]
- **描述**: 在 `ff_mjpeg_decode_sof()`（行 809-819）中，对 progressive JPEG 模式下的 `s->blocks[i]` 按 `size = bw * bh * h_count[i] * v_count[i]` 分配，其中 `bw = (width + h_max*8-1)/(h_max*8)`；同时 `block_stride[i] = bw * h_count[i]`。在 `ff_mjpeg_decode_sos()`（行 1753-1760）的非交错扫描路径中，`h = h_max / h_scount[0]`（C 整数除法向下取整），当 `h_max` 不能被 `h_count[c]`（= `h_scount[0]`）整除时（如 h_max=3, h_count[c]=2 → h=1），`mb_width = (width + h*8-1)/(h*8)` 被计算为远大于 `bw` 的值（约为 h_max/h 倍）。随后 DC 扫描（`mjpeg_decode_scan`）和 AC 扫描（`mjpeg_decode_scan_progressive_ac`）中的 `block_idx = mb_y * block_stride[c] + mb_x` 最大值超过 `size`，造成堆越界写。以 width=72、h_max=3（component-0 h_count=3）、h_count[c]=2 为例：bw=3，size=6，但 mb_width=9，block_idx 最大值=8，越界写 2 个 `int16_t[64]`（共 256 字节）至分配区之外的堆内存。
- **触发条件**: 攻击者构造含以下特征的畸形 JPEG 文件：① SOF2/SOF3（progressive）标记，至少 2 个分量，其中一个分量的 h_count（或 v_count）为某个不能整除 h_max（或 v_max）的值（如 h_count=2 且另一分量 h_count=3，或更普遍地 h_max % h_count[c] ≠ 0）；② SOS 标记以 nb_components_sos=1（非交错）扫描该分量，Ss 可为 0（DC 扫描）或非零（AC 扫描）。无需认证，仅需受害者解码该文件。
- **安全影响**: 堆越界写，写入内容为攻击者可部分控制的 DCT 系数值（由 Huffman 编码的 `level * quant_matrix[i]` 决定）。可导致堆元数据损坏，最坏情况下可被利用实现远程代码执行（RCE）；至少可造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
