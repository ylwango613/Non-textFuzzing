I've completed the full analysis of all 2897 lines, including: all block decode functions (mpeg1/mpeg2 intra/inter), CC caption parsing (A53/SCTE-20/DVD/Dish), sequence/extension header parsing, slice threading logic, and the IPU decoder. Here is my finding:

## VULN: ipu_decode_frame Heap OOB Write via Non-Aligned Height
- **漏洞类别**: memory-safety
- **函数**: ipu_decode_frame()
- **行号**: 2804-2854
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted .ipu media file
- **外部触发路径**: ffmpeg -i crafted.ipu -f null - -> avformat_open_input() -> ipu_read_header() [ipudec.c:61, reads height as raw avio_rl16 with no alignment check] -> avcodec_open2() -> ipu_decode_init() [no height validation] -> ipu_decode_frame() -> ff_get_buffer() [allocates frame for exact avctx->height rows, no macroblock padding] -> idct_put() writes to (y+8)*linesize OOB
- **描述**: `ipu_read_header()` (libavformat/ipudec.c:61) reads `st->codecpar->height = avio_rl16(pb)` from a 16-bit file header field with no alignment validation. When `height % 16 != 0` (e.g., height=17), `ff_get_buffer()` allocates a frame for exactly `avctx->height` luma rows. Inside `ipu_decode_frame()`, the outer loop `for (int y = 0; y < avctx->height; y += 16)` processes the last macroblock row at `y = height - height%16` (e.g., y=16 when height=17). The calls `m->idsp.idct_put(frame->data[0] + (y+8)*frame->linesize[0] + x, ...)` (lines 2847-2850) then write 8 rows of 8 bytes each starting at row `y+8` (e.g., row 24), which is `y+8 - height = 7` rows past the end of the allocated luma plane. This overwrites heap memory belonging to the chroma planes (U and V) or beyond the allocation, as the frame allocator does not add macroblock-row padding for the IPU codec.
- **触发条件**: 攻击者构造一个 `.ipu` 文件，将文件头偏移 10 字节处的 2 字节 height 字段设置为不是 16 的倍数的值（如 0x11 0x00 = 17）。该值通过探测检查（非零即可），被直接传入解码器，无需任何对齐验证。提供足够的有效 IPU 比特流使 `avpkt->size` 检查通过即可触发。
- **安全影响**: 堆缓冲区溢出（heap OOB write）可覆盖 chroma 平面的 AVBuffer 元数据或相邻堆块，在配合堆布局操控的条件下可实现任意代码执行（RCE）；最坏情况下至少造成进程崩溃（DoS）或信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
