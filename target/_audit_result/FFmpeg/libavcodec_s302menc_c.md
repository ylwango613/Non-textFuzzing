Now I have enough information to complete the analysis. Let me trace through the critical arithmetic carefully.

**`buf_size` computation (lines 76-78):**
```c
const int buf_size = AES3_HEADER_LEN +
                    (frame->nb_samples * nb_channels *
                    (avctx->bits_per_raw_sample + 4)) / 8;
```
All operands are `int`. With `nb_channels=2`, `bits_per_raw_sample=16`:
- multiplier = `2 * (16+4) = 40`
- `frame->nb_samples * 40` overflows `int` when `nb_samples ≥ 53,687,092`

**Wrap-around to zero (the dangerous case):**
- `gcd(40, 2^32) = 8`, so minimum wrap-to-zero is `nb_samples = 2^32/8 = 536,870,912`
- At that value: `536870912 * 40 = 21,474,836,480 = 5×2^32` → `= 0` in int32 arithmetic
- `buf_size = 4 + 0/8 = 4`

**The guard check at line 83 is bypassed:**
```c
if (buf_size - AES3_HEADER_LEN > UINT16_MAX)  // 4-4=0 > 65535 → false → passes!
```
The check catches negative overflow (signed→unsigned conversion makes it huge) but NOT the zero wrap-around to small positive value.

**Consequence:**
- `ff_get_encode_buffer(avctx, avpkt, 4LL, 0)` succeeds (4 > 0, passes the `size < 0` check)
- Allocates exactly 4 bytes
- `put_bits` header writes fill those 4 bytes exactly
- `o += AES3_HEADER_LEN` → `o` points 1 byte past the end of the 4-byte buffer
- The S16 write loop runs for 536,870,912 iterations × 5 bytes each = ~2.5 GB of writes off-heap

## VULN: Integer Overflow in buf_size Computation Bypasses Overflow Check Leading to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: s302m_encode2_frame()
- **行号**: 76-99
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_audio> -c:a s302m output.mxf -> avcodec_send_frame() -> s302m_encode2_frame()
- **描述**: 在 `s302m_encode2_frame()` 的第 76-78 行，`buf_size` 以有符号 `int` 运算计算：`AES3_HEADER_LEN + (frame->nb_samples * nb_channels * (bits_per_raw_sample + 4)) / 8`。所有操作数均为 `int`，当 `nb_samples` 足够大时，乘法在除以 8 之前发生 32 位有符号整数溢出。具体地，当 `nb_channels=2`、`bits_per_raw_sample=16` 时，`nb_samples=536870912`（= 2^32/8）使得 `nb_samples * 40` 恰好回绕为 0（即 `5×2^32 mod 2^32 = 0`），导致 `buf_size = 4`（即 `AES3_HEADER_LEN` 本身）。第 83 行的溢出防护检查 `buf_size - AES3_HEADER_LEN > UINT16_MAX`（即 `0 > 65535`）不成立而被绕过，因此该检查仅能捕获负溢出（由有符号转无符号隐式转换保护），无法检测到正方向的回绕小值。`ff_get_encode_buffer` 因此分配仅 4 字节的堆缓冲区，而后 `o += AES3_HEADER_LEN` 使 `o` 已超出缓冲区末尾，随后 S16 写循环对 536870912 个样本各写入 5 字节，共溢出约 2.5 GB 数据，造成大规模堆越界写。
- **触发条件**: 攻击者需构造一个音频输入，使解码器或 PCM demuxer 产生一个 `nb_samples = 536870912`（或使乘积 `nb_samples * nb_channels * (bits_per_raw_sample + 4)` 回绕为 0 的其他值）的单帧。例如：对于一个包含对应 2GB 原始 PCM S16 立体声数据的容器文件（block_align 配置使 demuxer 以单个超大包交付数据），由 PCM 解码器产生该帧后以 `-c:a s302m` 指定重编码时触发。具体文件类型可为 raw audio（.s16）或 MPEG TS 中植入的超大 PCM 包。
- **安全影响**: 堆越界写可覆盖 heap 元数据及相邻堆块，在能够控制 `nb_samples` 精确值的情况下可演化为任意代码执行（RCE）；在最坏情况下导致进程崩溃（DoS）。由于越界写范围达 GB 级，即使无法精确控制也会导致必然的进程崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
