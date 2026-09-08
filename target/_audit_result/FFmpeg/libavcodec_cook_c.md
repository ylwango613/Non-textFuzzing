I have completed the analysis. The code is carefully hardened for most bounds. I found one genuine OOB heap read.

**Key findings summary:**
- `decode_buffer_0[1060]` (line 162) is the joint-decode scratch buffer.
- In `joint_decode()` (lines 851–855), when `js_subband_start >= 27`, the read `decode_buffer[i * 40 + 20 + j]` where `i = js_subband_start − 1, j = 19` yields index `(js_subband_start−1)*40 + 39`. At `js_subband_start = 27`, this is index **1079**, 20 elements past the array end (1059). At max `js_subband_start = 50` (allowed; check is `< 51`) this reaches index **1999** — 940 elements past the end, reading into `cplscales[5]` pointers, `num_subpackets`, and `subpacket[MAX_SUBPACKETS]` (including `mono_previous_buffer1/2` float arrays within subpackets).
- The OOB read data flows through MDCT and gain compensation; heap pointer values interpreted as floats can produce extreme values; final clip in `saturate_output_float` has undefined behavior for NaN inputs.

## VULN: OOB Heap Read in joint_decode via js_subband_start
- **漏洞类别**: memory-safety
- **函数**: joint_decode()
- **行号**: 851-855
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted RealMedia (.rm) file with COOK audio
- **外部触发路径**: `ffmpeg -i crafted.rm -f null -` → `avformat_open_input()` → RM demuxer → `avcodec_open2()` → `cook_decode_init()` → `cook_decode_frame()` → `decode_subpacket()` → `joint_decode()`
- **描述**: 在 `joint_decode()` 的第 851–855 行，循环 `for (i = 0; i < p->js_subband_start; i++)` 以 `i * 40 + 20 + j` 为索引读取 `decode_buffer_0[1060]`（联合立体声解码暂存缓冲区）。当 `js_subband_start >= 27` 时，`(js_subband_start−1)*40 + 39` 超过数组边界 1059，产生堆越界读取。`js_subband_start` 仅被 `< 51` 检查（line 1124），允许攻击者将其设置为 27–50；同时约束 `total_subbands = subbands + js_subband_start <= 53`（line 1216）可以满足，例如 `js_subband_start = 50, subbands = 3`（total = 53）。在最坏情况下读取越界达 `(50−1)*40 + 39 = 1999` 处，即越过 `decode_buffer_0` 末尾 940 个 float（3760 字节），读入后续结构体成员：`cplscales[5]`（5 个 8 字节指针）、`num_subpackets`、及 `subpacket[MAX_SUBPACKETS]`（含 `mono_previous_buffer1/2` 各 1024 个 float）。被越界读取的数据（堆指针值被解释为 float）作为 MLT 系数传入 MDCT 变换和增益补偿链，可能产生 NaN/Inf 浮点值；`saturate_output_float` 对 NaN 的 clip 行为是实现定义的，在部分架构可导致浮点异常或静默的错误输出。
- **触发条件**: 攻击者构造一个 COOK 联合立体声 RealMedia (.rm) 音频文件，设置 extradata 中的 `js_subband_start >= 27` 且 `subbands <= 26`（保证 `total_subbands <= 53`），同时将 `cookversion` 设为 `JOINT_STEREO (0x1000003)`，`channels = 2`。
- **安全影响**: 堆越界读取暴露了解码器上下文（COOKContext）中的相邻结构字段，包括 VLC 表指针和音频暂存缓冲区内容，可能造成有限的堆信息泄露（通过音频帧输出）；在特殊浮点值传播的情形下可导致解码器产生错误输出（DoS-级别的功能中断），若 NaN 传播触发信号量（SIGFPE）则进程崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
