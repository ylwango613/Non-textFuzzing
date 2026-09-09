Now I have enough context. Let me trace the arithmetic precisely for the `add_wave` OOB.

**Key facts:**
- `fft_buffer[4][8192 * 2]` → each row has **16384** float elements (indices 0–16383)
- `fft_offset` toggles: first `decode_frame` call sets `fft_offset = frame_size − 0 = 8192`
- For group=0: `group_bits=4`, loop runs **31** iterations, `subframe_size=256`
- Tone `offset` can reach **16** (after one while-loop trip: `pos2=4096 < frame_size=8192`, `off=16`)
- `pos = freq >> 4`; `freq < group_size−1 = 4095` → `pos ≤ 255`

**Starting index B** (fft_offset=8192, offset=16, pos=255):
`B = 8192 + 256×16 + 255 = 12543`

**Loop iteration k=15** (no wrap fired yet — check is `imptr >= 16384` after increment):
`imptr = 12543 + 15×256 = 16383` (≡ valid index, so no wrap fires)
→ `imptr[0] = fft_buffer[stereo_mode][16383]` ✓
→ `imptr[1] = fft_buffer[stereo_mode][16384]` **OOB**

For `stereo_mode=1`, `reptr = &fft_buffer[3][...]`:
`reptr[1]` at index 16384 = **one past the entire `fft_buffer[4][16384]` member**, landing in `noise2_buffer[0]`.

The wrap guard on line 572 uses only `imptr` (not `imptr+1`), so it misses this case.

---

## VULN: add_wave() off-by-one OOB write past fft_buffer into noise2_buffer
- **漏洞类别**: memory-safety
- **函数**: add_wave()
- **行号**: 561-576
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted QDMC audio file
- **外部触发路径**: `ffmpeg -i <crafted_qdmc_file> -f null -` → `avformat_open_input()` → demuxer → `avcodec_send_packet()` → `qdmc_decode_frame()` → `decode_frame()` → `add_waves()` → `add_wave(group=0, offset=16, freq∈[4080,4094], stereo_mode=1)` → loop iteration k=15 → `reptr[1]` writes to `fft_buffer[3][16384]` → `noise2_buffer[0]`
- **描述**: `add_wave()` 内的循环每次迭代将 `imptr`/`reptr` 向前移动 `subframe_size`（256）个元素，并在移动后检查是否超出边界：`if (imptr >= &fft_buffer[stereo_mode][2*frame_size])`。该检查仅对 `imptr` 本身（基地址）进行校验，但在写入时同时访问 `imptr[0]` 和 `imptr[1]`。当 `imptr` 恰好落在数组最后一个合法元素 `fft_buffer[stereo_mode][16383]` 时，`imptr` 值本身满足 `< 16384`（不触发 wrap），但 `imptr[1]` 访问的是 `fft_buffer[stereo_mode][16384]`，越界一个 float（4 字节）。触发条件：`fft_offset = frame_size = 8192`（第二帧及之后每隔一帧）、group=0、`offset=16`、`pos=255`，循环第 16 次迭代（k=15）时 imptr=16383，执行 `imptr[1] -= im`。对于 `stereo_mode=1`，`reptr = &fft_buffer[3][base]`，对应的 `reptr[1]` 越过整个 `fft_buffer[4][16384]` 成员，写入 `QDMCContext.noise2_buffer[0]`。
- **触发条件**: 攻击者构造包含 QDMC 编码音频轨道的媒体文件（如 MOV/MP4 容器），extradata 中设置 `sample_rate ≥ 32000`（使 `frame_bits=13`、`frame_size=8192`、`subframe_size=256`），且在第 2 帧（`fft_offset` 切换为 8192）开始后，在 group=0 的音调比特流中构造 VLC 码字，使 `off=16`（while 循环执行一次：`pos2=4096 < 8192`，`off+=16`）且 `freq ∈ [4080,4094]`（`pos=freq>>4=255`），并指定 `stereo_mode=1`（双声道场景）。
- **安全影响**: 越界写入一个 float 值（来自 `amplitude_tab × alt_sin × sin_table` 的乘积，取值有限但非零）覆盖 `QDMCContext.noise2_buffer[0]`，导致后续 `add_noise()`/`lin_calc()` 计算产生错误，可能引发浮点异常或 crash（DoS）；在极端情况下，若利用内存布局精确控制覆盖目标，存在进一步内存破坏的潜在风险。

<!-- AUDIT_PROMPT_VERSION: 1 -->
