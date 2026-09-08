I've completed my analysis. Here is my confirmed finding set — two distinct heap out-of-bounds write vulnerabilities in `argo.c`:

---

## VULN: decode_mad1 case-8 OOB Write Due to Missing Partial-Row-Block Guard
- **漏洞类别**: memory-safety
- **函数**: decode_mad1()
- **行号**: 159-173
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (AVI/BRP container with Argo codec, 8bpp PAL8 mode)
- **外部触发路径**: `ffmpeg -i evil.avi -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `decode_frame()` → `decode_mad1()` → case 8 inner `memset` loop
- **描述**: 在 `decode_mad1()` 的 case 8 分支，外层循环条件为 `for (int y = 0; y < h; y += 8)`（行 161），仅要求 `y < h` 而非 `y + 8 <= h`，因此当帧高度不是 8 的整数倍时，最后一次迭代对应的 y 值使剩余有效行数不足 8。内层循环 `for (int by = 0; by < 8; by++)` 无条件写满 8 行（`memset(ddst, fill, 8); ddst += l;`），导致指针 `ddst` 超出 `frame->data[0]` 所分配的 `linesize[0] * height` 字节缓冲区，最多溢出 `7 * linesize[0]` 字节。由于 `decode_init()` 仅检查 `width % 2 == 0 && height % 2 == 0`，不要求高度是 8 的倍数，攻击者可以将容器头中的帧高度设置为任意偶数（如 h=10，h=2，h=6 等）来触发此溢出。相比之下，`decode_mad1_24()` 中的 case 8 使用了正确的 `y + 12 <= h` 边界守卫（行 372），表明此处缺少守卫是一个遗漏。
- **触发条件**: 构造一个使用 Argo 视频编解码器（AV_CODEC_ID_ARGO）的 AVI 容器文件，`bits_per_coded_sample=8`，帧高度设为非 8 倍数的偶数（例如 h=10），并在 payload 中写入 type=8 的 MAD1 块（首字节 `0x08`）。帧缓冲区约为 `linesize * 10 + ~64` 字节，内层循环会将指针推进到 row 10–15，超出分配范围。
- **安全影响**: 攻击者控制 `fill` 值（来自 `bytestream2_get_byte(gb)` 读取的每个 8×8 块的填充字节），可将任意字节写入帧缓冲区末尾之后的堆内存，覆盖相邻堆块的元数据或其他对象，最坏情况下可导致远程代码执行（RCE）。

## VULN: decode_mad1_24 case-12 OOB Write Due to Missing dy Bounds Check Against Frame Height
- **漏洞类别**: memory-safety
- **函数**: decode_mad1_24()
- **行号**: 460-550
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (AVI/BRP container with Argo codec, 24bpp BGR0 mode)
- **外部触发路径**: `ffmpeg -i evil.avi -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `decode_frame()` → `decode_mad1_24()` → case 12 inner `dst[0] = ...` write
- **描述**: 在 `decode_mad1_24()` 的 case 12 分支，外层 y 循环为 `for (int y = 0; y < h; y += 4)`（行 460），条件仅是 `y < h` 而非 `y + 4 <= h`。每次进入该块时，内层 `for (int count = 0; count < 4; count++)` 无条件将 `dy = y + count` 设置为 y, y+1, y+2, y+3，并计算 `dst = (uint32_t *)frame->data[0] + pos + dy * l`（行 472–473），然后直接向 `dst[0]` 写值（bcode 驱动的 case 1/2/3 分支）。当 `h % 4 != 0`（仍为偶数，如 h=10）时，最后一次 y 迭代（y=8）使 `dy` 取值 8、9、10、11，其中 `dy=10` 和 `dy=11` 超过帧高度 `h=10`，对应的 `dst` 指向 `frame->data[0] + 10*l*4` 及以后，超出帧缓冲区末尾。代码中没有对 `dy < h` 的守卫检查。代码中同样位于 `decode_mad1_24` 的 case 8 使用了正确的 `y + 12 <= h` 条件（行 372），进一步印证 case 12 此处缺少等价守卫是一个 bug。
- **触发条件**: 构造一个使用 Argo 视频编解码器的 AVI 容器文件，`bits_per_coded_sample=24`，帧高度设为非 4 倍数的偶数（如 h=10, h=6, h=14），并在 MAD1 块内写入 type=12（`0x0C`）子类型；将 bitmap 中对应 (x=0, y=8) 这一 4×4 块的位置 1，并在 codes 字节中设置 code != 0 以触发写操作。
- **安全影响**: 写入的值可以是 `dst[-1]`（前一像素）、`dst[-l]`（前一行像素）或通过 `bytestream2_get_be16(gb)` 读取的攻击者任意构造值（code==3, v>=128 时 `dst[0] = ((v & 0x7F) << 17) | attacker_u16`）。向帧缓冲区末尾以后写入攻击者控制的 uint32_t 值，可以破坏相邻堆对象，最坏情况下可实现堆利用并导致远程代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
