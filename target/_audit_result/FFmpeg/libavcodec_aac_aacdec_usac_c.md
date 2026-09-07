I have completed a thorough multi-pass audit of the entire 2208-line file and traced all relevant function implementations. Here are my confirmed findings:

## VULN: Unbounded Mutual Recursion Causing Stack Overflow via Nested Audio Preroll
- **漏洞类别**: memory-safety
- **函数**: `parse_audio_preroll()` / `ff_aac_usac_decode_frame()` / `parse_ext_ele()`
- **行号**: 1888-1959 / 1951 / 2034 / 2054-2208 / 2139-2143
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (.m4a / .aac / M4A container)
- **外部触发路径**: `ffmpeg -i <file> -f null -` → `avformat_open_input()` → AAC decoder init → `ff_aac_usac_config_decode()` [sets up `ID_USAC_EXT` elem with type `ID_EXT_ELE_AUDIOPREROLL`] → first frame → `ff_aac_usac_decode_frame()` [line 2140] → `parse_ext_ele()` [line 2034] → `parse_audio_preroll()` [line 1951] → `ff_aac_usac_decode_frame()` → `parse_ext_ele()` → `parse_audio_preroll()` → … (unbounded)
- **描述**: `parse_audio_preroll()` (line 1951) calls `ff_aac_usac_decode_frame()` to decode embedded preroll frames. That function (line 2140) calls `parse_ext_ele()`, which for a `ID_EXT_ELE_AUDIOPREROLL` extension element calls `parse_audio_preroll()` again (line 2034). There is no recursion depth counter or guard anywhere in this call chain. Because the attacker fully controls the contents of each preroll frame—including configuring a nested `ID_USAC_EXT` + `ID_EXT_ELE_AUDIOPREROLL` element—each recursive level maps directly to one additional stack frame. `parse_audio_preroll()` alone declares `uint8_t temp_data[512]` on the stack (line 1895) plus `MPEG4AudioConfig m4ac_bak`, `GetBitContext gbc`, and other locals, consuming ≥700 bytes per level. On a default 8 MB Linux thread stack, fewer than ≈11,000 recursion levels cause `SIGSEGV` via stack exhaustion. A crafted file of only ≈150 KB can encode 11,000 nesting levels (each level requires ≈15 bytes of bitstream: config_len + minimal USAC config + preroll header + inner au_len).
- **触发条件**: 构造一个 M4A/AAC 文件，其中：(1) USAC config 包含一个 `ID_USAC_EXT` 元素且 type 为 `ID_EXT_ELE_AUDIOPREROLL`；(2) 每一帧的 audio preroll 载荷中，又包含一个配置了 `ID_EXT_ELE_AUDIOPREROLL` 扩展元素的 USAC 子帧；(3) 将此嵌套结构重复约 11000 层（约 150KB 数据量即可达到）。
- **安全影响**: 确定性崩溃（DoS）。在某些平台/线程模型下，如果攻击者能精确控制 `temp_data[512]` 以下的栈内存布局，可能进一步演化为远程代码执行（RCE）。影响所有嵌入 USAC/xHE-AAC 解码器的 FFmpeg 版本。

## VULN: Out-of-Bounds Heap Read via Unchecked Large Bit-Skip in decode_usac_extension
- **漏洞类别**: memory-safety
- **函数**: `decode_usac_extension()`
- **行号**: 437-490，具体为第 484 行
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted USAC config in MP4 extradata or in-band
- **外部触发路径**: `ffmpeg -i <file.m4a> -f null -` → `avformat_open_input()` → MP4 demuxer passes extradata → `ff_aac_usac_config_decode()` → `decode_usac_extension()` [line 484] → OOB heap read → subsequent `get_bits()` in `ff_aac_usac_config_decode()` reads OOB memory
- **描述**: 在 `decode_usac_extension()` 中，`ext_config_len` 由攻击者控制的比特流字段 `get_escaped_value(gb, 4, 8, 16)` 读取（最大值为 `15 + 255 + 65535 = 65805`）。当 `e->ext.type` 为 `ID_EXT_ELE_AUDIOPREROLL` 或任何未知类型时，代码执行 `skip_bits(gb, 8 * ext_config_len)` （第 484 行），最多将 `GetBitContext.index` 推进 `8 × 65805 = 526440 bits = 65805 bytes`。对于典型 USAC extradata（通常 ≤ 100 bytes，含 64 bytes `AV_INPUT_BUFFER_PADDING_SIZE` 填充），该 skip 会使 `index` 指向 extradata 堆分配之外约 65700 字节处。之后 `ff_aac_usac_config_decode()` 继续调用 `get_bits1(gb)`（第 738 行）、`get_escaped_value(gb, ...)` 等，触发 `UPDATE_CACHE` 宏，该宏执行 `AV_RB32(s->buffer + (index >> 3))`，从超出 buffer 范围的堆内存地址处读取 4 字节，导致堆越界读取。
- **触发条件**: 构造一个 MP4 文件，其 USAC extradata 中包含一个 `ID_USAC_EXT` 元素，type 设置为 `ID_EXT_ELE_AUDIOPREROLL`（或任意未知 type），`usacExtElementConfigLength`（通过 escaped value 编码）设置为最大值 65805。由于 AUDIOPREROLL 元素理论上 config length 应为 0，FFmpeg 代码未对该字段做上界校验，直接执行过大的 skip。
- **安全影响**: 越界堆读取，可能导致：(1) `SIGSEGV` 崩溃（DoS），当越界地址所在内存页未映射时；(2) 读取相邻堆对象数据（信息泄露），若堆内存已映射；(3) 读取的垃圾数据被用于后续 loudness/extension 配置解析，可能引发二次破坏（不当的 nb_extensions 值导致大循环或二次越界读）。
