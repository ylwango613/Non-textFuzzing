I have enough context for the full analysis. Here is the final audit report:

## VULN: lead_decode_frame YUV444P heap OOB write via unchecked height alignment
- **漏洞类别**: memory-safety
- **函数**: lead_decode_frame()
- **行号**: 286-302
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_avi> -f null - -> avformat_open_input() -> avi_read_packet() -> avcodec_send_packet() -> lead_decode_frame() -> ff_idctdsp_init() -> idct_put() [OOB heap write]
- **描述**: 在 `lead_decode_frame` 的 YUV444P 分支（format=0x2000 或 0x2006，第 286-302 行），外层循环边界为 `j < (avctx->height + 7) / fields / 8`，即 `ceil(height/(fields*8))` 次迭代。每次迭代中 `decode_block` 调用 `idct_put`，从行 `(f + 8*j*fields)` 开始连续写 8 行像素（stride = `fields * frame->linesize`）。`avcodec_align_dimensions2` 对 YUV444P 的高度对齐仅为 `h_align = 1 << log2_chroma_h = 1`，即分配的帧缓冲区**恰好**只有 `avctx->height` 行。当 `avctx->height` 不是 `8*fields` 的整数倍时（例如 height=9，fields=1），最后一个 j 迭代（j=1）从第 8 行开始写，`idct_put` 写到第 8、9、10、11、12、13、14、15 行，而分配的缓冲区只有 9 行（行 0-8），导致 7 行的堆越界写。对于 fields=2（format 0x2006），类似的情况在高度不是 16 的倍数时发生。
- **触发条件**: 攻击者构造一个 AVI 文件，编解码器标签指向 LEAD（FourCC "LEAD" 或对应的 codec_id），在容器中将视频流的 height 设置为不是 8（fields=1）或 16（fields=2）整数倍的值（如 height=9），并在每一帧前 2 字节偏移 4 处写入 format=0x2000（YUV444P）。
- **安全影响**: 攻击者可控制解码帧的像素数据（来自 IDCT 输出），能够精确控制越界写入的值，覆盖紧邻帧缓冲区之后的堆内存（可能包含其他帧的 data 指针、元数据结构），在最坏情况下可实现堆布局操控并达到远程代码执行（RCE）；最低限度造成进程崩溃（DoS）。

## VULN: lead_decode_frame YUV420P heap OOB write via unchecked height alignment
- **漏洞类别**: memory-safety
- **函数**: lead_decode_frame()
- **行号**: 253-285
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_avi> -f null - -> avformat_open_input() -> avi_read_packet() -> avcodec_send_packet() -> lead_decode_frame() -> decode_block() -> idct_put() [OOB heap write in luma and chroma planes]
- **描述**: 在 `lead_decode_frame` 的 YUV420P 常规分支（formats 0x1000/0x6/0x8000/0x1006），宏块行循环边界为 `mb_y < (avctx->height + 15) / 16 / fields = ceil(height/(16*fields))`。对于亮度块（b=2,3，`b>>1=1`），写入行坐标 `y = 16*mb_y + 8`；最后一次迭代（last `mb_y = ceil(height/16)-1`）使 y = 16*(ceil(height/16)-1)+8，`idct_put` 再向后写 8 行，最大访问行 = 16*ceil(height/16)+7。`avcodec_align_dimensions2` 对 YUV420P 的 `h_align=2`，仅将帧高对齐到偶数。以 height=17 为例：分配亮度平面 18 行，but 最大写入行 = 16*2+7 = 39，远超 18 行。色度平面（b=4,5）访问行 `8*mb_y` 到 `8*mb_y+7`；height=17 时色度高度 9 行，最后一次 `mb_y=1` 写到第 8-15 行，越界 7 行。同一路径中 `copy_block8`（第 282-284 行）以步幅 `2*linesize` 从行 `y+1` 开始再写 8 组，访问行 y+1,y+3,...,y+15，进一步加深越界范围。
- **触发条件**: 攻击者构造一个 AVI 文件，LEAD codec，在容器中将视频流 height 设置为非 16 的整数倍（如 height=17），帧头部偏移 4 处 format 字节设为 0x1000（YUV420P）、0x6（yuv420p_half）或 0x8000（yuv420p_half），帧内容满足最小码流大小校验即可。
- **安全影响**: 越界写入覆盖堆中紧邻亮度/色度缓冲区之后的内存（可能包含解码上下文、AVFrame 指针等），写入内容为攻击者可通过构造 DCT 系数间接控制的整数值，最坏情况可通过堆风水实现任意代码执行（RCE）；最低限度造成崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
