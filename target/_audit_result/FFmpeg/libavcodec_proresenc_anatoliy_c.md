The arithmetic confirms the vulnerability: at exactly **16384 × 16384** (or **65534 × 65535**), `FFALIGN(w,16) * FFALIGN(h,16) * 16` wraps to **0** in 32-bit signed integer arithmetic, making `frame_size = 16884` bytes. `ff_alloc_packet` allocates only **33 268 bytes**, but the encoder subsequently writes a full-sized frame's worth of data — causing a heap buffer overflow.

## VULN: Integer Overflow in frame_size → Heap Buffer Overflow in prores_encode_frame
- **漏洞类别**: memory-safety
- **函数**: prores_encode_frame()
- **行号**: 736-739
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: `ffmpeg -i crafted.mkv -c:v prores_aw output.mov` → `avcodec_encode_video2()` → `prores_encode_frame()` → integer overflow at line 736 → `ff_alloc_packet()` allocates 33268 bytes → `prores_encode_picture()` writes actual frame data far exceeding the buffer → heap overflow
- **描述**: 在 `prores_encode_frame()`（第 736 行）中，`frame_size` 被声明为 `int`，其计算式为 `FFALIGN(avctx->width, 16) * FFALIGN(avctx->height, 16) * 16 + 500 + FF_INPUT_BUFFER_MIN_SIZE`。当帧宽/高使得 `FFALIGN(w,16) * FFALIGN(h,16)` 为 2^28 的整数倍时（例如 w=h=16384：`16384 * 16384 = 268435456`，再乘以 16 得 `4294967296 = 2^32`），32 位有符号整数回绕至 **0**，导致 `frame_size = 0 + 500 + 16384 = 16884`。随后 `ff_alloc_packet(avctx, pkt, frame_size + FF_INPUT_BUFFER_MIN_SIZE)` 仅分配 33268 字节的包缓冲区。编码器接着调用 `prores_encode_picture()`，为完整的 16384×16384 帧写入远超缓冲区容量的数据：slice 大小表指针 `sl_data_sizes + (slice_per_line * mb_height * 2)` 直接落在分配区域之外（约 4MB 偏移），并循环向该越界地址写入切片数据，造成堆溢出。编码器自身在 `prores_encode_init()` 第 835-838 行对宽度（≤65534）和高度（≤65535）进行了上界校验，但这并不阻止整数溢出——最大允许值 65534×65535 同样触发相同的回绕（`FFALIGN(65534,16)=65536`，`65536*65536=2^32 ≡ 0`）。
- **触发条件**: 攻击者构造一个包含视频流的容器文件（如 MKV/MP4），声明帧尺寸恰好使 `FFALIGN(w,16) * FFALIGN(h,16)` 为 2^28 倍数（最小实用值：w=h=16384；最大允许值：w=65534,h=65535 同样触发），然后通过 `ffmpeg -c:v prores_aw` 或 `prores` 转码该文件。
- **安全影响**: 堆越界写（heap OOB write），可导致：(1) 可靠的进程崩溃（拒绝服务）；(2) 若攻击者可控制输入帧像素内容，结合堆布局控制，可能实现任意代码执行（RCE）。在自动化视频转码服务场景中，服务端进程可在无用户交互下直接处理攻击者文件，危害尤为严重。

<!-- AUDIT_PROMPT_VERSION: 1 -->
