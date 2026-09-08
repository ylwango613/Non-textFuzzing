Now I have a complete picture. Let me trace the exact vulnerability:

**Findings from analysis:**

**`fastaudio_decode` line 116**: The bound check is `subframes > INT_MAX / 256` (= 8388607), but the memcpy at line 173 uses `1024 * subframe` (= 4 × 256 × subframe) as a byte offset — 4× tighter overflow limit. When `subframe ≥ 2097152`, `1024 * subframe` overflows `int32` to a large negative value, making the memcpy destination pointer go 2 GB before the frame buffer.

**Trigger path from moflex.c**: The MOFLEX demuxer reads `channels = avio_r8(pb) + 1` (1–256, from file), no upper limit on accumulated `pkt->size` (chunks appended across many blocks via `av_append_packet` with no size cap). An attacker crafting a MOFLEX file with 1 audio channel and accumulating ~80 MB of audio data in a single packet reaches `subframes = 2097153`, bypassing the faulty check.

**Confirmed**: Python confirms `ctypes.c_int32(1024 * 2097152).value = -2147483648` (wraps to INT_MIN).

## VULN: Integer overflow in memcpy offset causes OOB write in fastaudio_decode
- **漏洞类别**: memory-safety
- **函数**: fastaudio_decode()
- **行号**: 116-173
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MOFLEX media file
- **外部触发路径**: `ffmpeg -i crafted.moflex -f null -` → `avformat_open_input()` → `moflex_read_packet()` → `av_append_packet()` (accumulates >83 MB audio packet across many blocks) → `fastaudio_decode()` → integer overflow at `1024 * subframe` → `memcpy()` with underflowed destination pointer
- **描述**: 在 `fastaudio_decode`（第116行）对 `subframes` 的上界检查使用了错误的除数 `INT_MAX / 256 = 8388607`，而第173行 `memcpy` 中的字节偏移量是 `1024 * subframe`（= 4 × 256 × subframe），其溢出临界点是 `INT_MAX / 1024 = 2097151`。当攻击者通过 MOFLEX 容器提供 `pkt->size ≥ 83886120`（约80 MB）的单声道音频包时，`subframes = 2097153`，绕过第116行的检查。在后续循环迭代 `subframe = 2097152` 时，`1024 * 2097152 = 2147483648 > INT_MAX`，发生有符号整数溢出（C 语言 UB），在 x86-64 上回绕为 `INT_MIN = -2147483648`。`memcpy` 的目标地址变为 `frame->extended_data[channel] - 2147483648`，写入位置在已分配帧缓冲区之前约 2 GB 处，导致越界写入。
- **触发条件**: 构造一个 MOFLEX 文件，音频流 `channels` 字节值为 0（解析为 1 通道），通过在多个数据块（block）中设置 `endframe=0` 并持续追加音频块（`av_append_packet`），最终 `pkt->size` 超过 `2097153 × 40 ≈ 80 MB`，最后一块设 `endframe=1` 投递该超大包给解码器。系统需有约 2 GB 可用内存供帧缓冲区分配成功。
- **安全影响**: 触发时 `memcpy` 目标地址在已分配帧缓冲区 2 GB 之前，在现代 64 位系统（ASLR 启用）上大概率命中未映射虚拟地址，导致 SIGSEGV（可靠崩溃/DoS）。在内存布局特殊（低地址堆分配或大页映射）的场景下，可能写入其他堆对象，进一步有潜在 RCE 风险。

<!-- AUDIT_PROMPT_VERSION: 1 -->
