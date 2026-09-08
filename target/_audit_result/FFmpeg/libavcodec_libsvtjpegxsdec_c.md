Now I have complete context. Let me analyze the critical code paths:

**Group 1 (lines 93-180) — `svt_jpegxs_dec_decode` decode path analysis:**

- Line 100-105: `svt_jpeg_xs_decoder_get_single_frame_size_with_proxy` fills `svt_dec->config` (components_num, width, height, format) from attacker-controlled bitstream.
- Line 115-139: Re-initialization branch — if `decoder_initialized=1` and format/dims differ from previous frame, old decoder is closed (line 122), then `svt_jpeg_xs_decoder_init` is called. **If init fails (line 125-128), function returns immediately leaving `decoder_initialized` still set to 1, but the underlying SVT decoder was already closed at line 122.**
- Line 186 (`svt_jpegxs_dec_free`): Calls `svt_jpeg_xs_decoder_close` **unconditionally**, no check of `decoder_initialized`. This creates a double-close on the already-closed decoder.

**Group 2 (lines 153-158) — components_num loop:**

- Loop bound `svt_dec->config.components_num` is attacker-controlled from bitstream.
- `picture->data[comp]` and `picture->linesize[comp]` arrays have 8 slots (AV_NUM_DATA_POINTERS=8).
- All supported pixel formats are 3-plane YUV, so `components_num` should be 3 for valid streams; unusual values would be constrained by the library.

**Group 3 — init/close without `decoder_initialized` check:**

- `svt_jpegxs_dec_init` does not call `svt_jpeg_xs_decoder_init` (only sets a few config fields).
- `svt_jpegxs_dec_free` always calls `svt_jpeg_xs_decoder_close` — if no frames were ever decoded (`decoder_initialized=0`), this calls close on a struct that was never properly initialized by the SVT library.

**Confirmed bug: double-close via decoder re-init failure path (lines 121-128 + 186)**

The state machine is:
1. Frame 1 decoded → `decoder_initialized=1`, SVT decoder properly initialized
2. Frame 2 arrives with different width/height/format → re-init branch taken → `svt_jpeg_xs_decoder_close` called (line 122), `decoder_initialized` still 1
3. `svt_jpeg_xs_decoder_init` fails → returns `AVERROR_EXTERNAL` at line 127 **without** resetting `decoder_initialized=0`
4. `avcodec_close` → `svt_jpegxs_dec_free` → `svt_jpeg_xs_decoder_close` called again on an already-closed SVT decoder context → double-close, potential double-free of library internals

This is a real CWE-415 double-free/double-close with external trigger via a crafted two-frame JPEG XS stream.

## VULN: Double-Close of SVT Decoder Context After Re-init Failure
- **漏洞类别**: memory-safety
- **函数**: svt_jpegxs_dec_decode() / svt_jpegxs_dec_free()
- **行号**: 121-128 / 186
- **CWE**: CWE-415 (Double Free)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_jpegxs_file> -f null - → avformat_open_input() → avcodec_send_packet() → svt_jpegxs_dec_decode() [Frame 1: decode OK, sets decoder_initialized=1] → svt_jpegxs_dec_decode() [Frame 2: triggers re-init branch at line 119, closes decoder at line 122, svt_jpeg_xs_decoder_init fails at line 125-128, returns without resetting decoder_initialized] → avcodec_close() → svt_jpegxs_dec_free() → svt_jpeg_xs_decoder_close() called again on already-closed SVT decoder context
- **描述**: `decoder_initialized` 标志在重初始化分支（lines 119-139）中发生失败时未被重置为 0：当 `svt_dec->decoder_initialized=1` 且格式/尺寸变化触发重初始化时，代码在 line 122 先调用 `svt_jpeg_xs_decoder_close` 关闭 SVT 解码器内部上下文（释放内部缓冲区和线程资源），随后调用 `svt_jpeg_xs_decoder_init`，若此调用失败则在 line 127 直接 `return AVERROR_EXTERNAL`，而 `decoder_initialized` 仍保持为 1。此后 `avcodec_close()` 触发 `svt_jpegxs_dec_free()`，该函数无条件调用 `svt_jpeg_xs_decoder_close(&svt_dec->decoder)`（line 186）——对同一个已被关闭/销毁的 SVT 解码器上下文执行第二次关闭，造成 double-free。
- **触发条件**: 攻击者构造一个包含至少两帧的畸形 JPEG XS 文件（可封装在 MXF/QuickTime/MPEG-TS 容器中）：第 1 帧为合法 JPEG XS 帧（使解码器成功初始化，`decoder_initialized` 置 1）；第 2 帧具有不同的宽/高或颜色格式字段（触发 lines 119-139 的重初始化路径），且 `svt_jpeg_xs_decoder_get_single_frame_size_with_proxy` 返回成功但后续 `svt_jpeg_xs_decoder_init` 失败（例如 bitstream 头部经精心构造，使帧尺寸字段合法但内部编码参数无效）。
- **安全影响**: `svt_jpeg_xs_decoder_close` 的第二次调用对已释放的内部 SVT 上下文（含线程句柄、内部帧缓冲区指针）执行再次释放操作，可导致堆内存损坏。在 glibc tcache/fastbin 双重释放保护较弱或可绕过的条件下，可能被利用实现任意代码执行（RCE）；最低影响为可重复触发的进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
