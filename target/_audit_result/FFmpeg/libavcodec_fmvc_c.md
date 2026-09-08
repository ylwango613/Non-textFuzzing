数値計算が確認されました。脆弱性が確定です。最終レポートを出力します。

## VULN: FMVC decoder heap OOB write via integer overflow in buffer_size
- **漏洞类别**: memory-safety
- **函数**: decode_init() / decode_frame()
- **行号**: 616-619 (underallocation) / 505-511 (OOB write)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (e.g., AVI with FMVC codec)
- **外部触发路径**: ffmpeg -i crafted.avi -f null - -> avformat_open_input() -> avi_read_packet() -> avcodec_send_packet() -> decode_frame() [fmvc.c] -> XOR write loop (line 509: `*dst++ ^= *src++`)
- **描述**: 在 `decode_init()`（第616行）中，`s->buffer_size = avctx->width * avctx->height * 4` 的计算使用 `int * int * int = int` 32位有符号整数算术，结果赋给 `size_t`。当 `width=32768, height=32769, bits_per_coded_sample=32` 时：`32768 × 32769 × 4 = 4,295,098,368`，溢出为 `131072`（即128KB）。`av_mallocz(131072)` 成功分配，但实际所需约4GB。在非关键帧（P帧）解码路径（`decode_frame` 第496-517行），XOR循环通过裸指针 `*dst++ ^= *src++` 以步长 `s->stride=32768 DWORDs` 遍历整个帧的块结构：处理完第0行（112行高）的所有块后，`dst` 被设置为 `s->buffer + 112 × 32768 × 4 = s->buffer + 14,680,064 字节`，而缓冲区仅有131,072字节。当第1行（offset ≥ 390）的任何块带有 `xor=1` 标志时，`*dst++ ^= *src++` 向14MB越界处写入堆内存。**关键点**：此XOR写操作发生在 `ff_get_buffer()`（第519行）之前，因此不依赖大帧缓冲区的成功分配，越界写入必然触发。`bytestream2` 的EOF保护机制仅约束 `pb`（pbuffer）写入，对直接指针算术的XOR写无任何防护。
- **触发条件**: 攻击者构造 AVI 文件，FMVC 视频流参数为：`biWidth=32768, biHeight=32769, biBitCount=32`。`decode_init` 分配131,072字节的 `s->buffer`。随后发送非关键帧，设置 `nb_blocks=1`，`offset=390`（位于第1行）；相应压缩数据解压后产生恰好 `9408×4=37632` 字节，通过块大小校验。XOR循环在处理完第0行后 `dst` 已越界，对第1行块执行 `*dst++ ^= *src++` 时写入 `s->buffer` 之后约14MB处的堆内存。
- **安全影响**: 最坏情况：若越界写入落在相邻的已映射堆区域（如同进程其他 `mmap` 段），可实现任意堆内存破坏，进而提权至远程代码执行（RCE）。在典型64位Linux系统上（`s->buffer` 通过 `mmap` 分配，128KB=MMAP_THRESHOLD），越界写入命中未映射页，导致 SIGSEGV 崩溃（DoS）。无论哪种情况，越界写均可靠触发，DoS 可被任意未经验证的攻击者通过提供一个畸形媒体文件来实现。

<!-- AUDIT_PROMPT_VERSION: 1 -->
