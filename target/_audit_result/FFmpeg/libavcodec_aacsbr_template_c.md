I have fully analyzed the file. Here is the final audit report:

## VULN: Heap OOB Write via Unchecked n_master in sbr_make_f_master
- **漏洞类别**: memory-safety
- **函数**: sbr_make_f_master()
- **行号**: 473-479
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted AAC audio file (HE-AAC/SBR bitstream)
- **外部触发路径**: ffmpeg -i crafted.aac -f null - → avformat_open_input() → avcodec_open2() → ff_aac_sbr_decode_extension() / ff_aac_sbr_decode_usac_data() → sbr_reset() → sbr_make_f_master() [heap OOB write at line 478]
- **描述**: `f_master` is declared as `uint16_t f_master[49]` in `SpectralBandReplication` (sbr.h:182), meaning valid indices are 0–48. In `sbr_make_f_master` the logarithmic branch (when `spectrum->bs_freq_scale != 0`) computes `sbr->n_master = num_bands_0 + num_bands_1` without enforcing an upper bound: `check_n_master` at line 474 only verifies `n_master > 0` and `bs_xover_band < n_master`, never that `n_master ≤ 48`. For a crafted bitstream at 192 kHz with `bs_start_freq=0` (→ k0=1), `bs_stop_freq` tuned to yield k2=33 (k2−k0=32 = max_qmf_subbands, which passes the ≤ check at line 346), `bs_freq_scale=1` (half_bands=6) and `bs_alter_scale=0` (invwarp=1.0): `num_bands_0 = round(6 × log2(2/1)) × 2 = 12`, `num_bands_1 = round(6 × log2(33/2)) × 2 = 48`, giving `n_master = 60`. The `memcpy` at line 478 then writes 48 × 2 = 96 bytes starting at `f_master[13]`, reaching `f_master[60]` — overflowing by 12 `uint16_t` values (24 bytes) into the adjacent heap field `f_tablelow[0..11]`. The heap-allocated `ExtChannelElement` contains `SpectralBandReplication` inline, so the consecutive struct members (`f_tablelow[25]`, `f_tablehigh[49]`, `f_tablenoise[6]`, `f_tablelim[30]`) are overwritten. The same corrupted `n_master` subsequently triggers a second OOB write in `sbr_make_f_derived` (line 562-563): `memcpy(f_tablehigh, f_master, (n[1]+1) × 2)` writes 61 × 2 bytes into `f_tablehigh[49]` (49 entries), overflowing into `f_tablenoise`; and the loop at line 580-581 writes `f_tablelow[25..30]` OOB (f_tablelow has only 25 entries).
- **触发条件**: 攻击者构造一个 HE-AAC / AAC-SBR 音频文件，设置采样率为 192 000 Hz（或 176 400 Hz），在 SBR 头中令 `bs_start_freq=0`（使 k0 最小化为 1）、`bs_stop_freq` 选择使 k2 达到 k0+32=33（恰好通过 `> max_qmf_subbands` 检查）、`bs_freq_scale=1`、`bs_alter_scale=0`。此配置无需任何用户认证，只需将该文件传递给 `ffmpeg -i` 或任何调用 FFmpeg 解码 HE-AAC 的应用程序。
- **安全影响**: 在堆上连续写入最多 12 个 `uint16_t`（24 字节），破坏 `f_tablelow`、`f_tablehigh` 等后续频带表的值。被污染的频带表被用作数组索引访问 QMF 子带缓冲区（如 `X_high[64][40][2]`、`e_origmapped[8][48]`），可进一步触发二次 OOB 读写，在精心构造的条件下可实现任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
