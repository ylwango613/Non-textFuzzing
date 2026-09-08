Now I have all the information needed. Let me document the confirmed findings.

**Key findings:**
1. `sbr->m[1]` is bounded only by `kx[1] + m[1] <= 64` (template.c:568), but NO check `m[1] <= 48`
2. Arrays `gain[8][48]`, `q_m[8][48]`, `s_m[8][48]`, `e_curr[8][48]`, `g_temp[42][48]`, `q_temp[42][48]` all cap at 48
3. At 192 kHz SBR rate with `bs_start_freq=0`, `k[0] = 3 + (-2) = 1`, so `kx[1] = 1` and `m[1]` can reach 63
4. Stack array `g_filt_tab[48]` in `sbr_hf_assemble` (aacsbr_fixed.c:531) is overrun when `m_max > 48`
5. Heap OOB writes in `sbr_gain_calc` (aacsbr_fixed.c:418-453) overwrite beyond `gain[8][48]` into adjacent `qmf_filter_scratch` and function pointers

---

## VULN: Stack Buffer Overflow in sbr_hf_assemble via Unchecked m[1] > 48
- **漏洞类别**: memory-safety
- **函数**: sbr_hf_assemble()
- **行号**: 531-549 (aacsbr_fixed.c); root cause in sbr_make_f_derived() at aacsbr_template.c:568
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted AAC media file with embedded SBR extension
- **外部触发路径**: ffmpeg -i <crafted_aac_or_mp4> -f null - → avformat_open_input() → ff_aac_sbr_decode_extension_fixed() → sbr_reset() → sbr_make_f_derived() [sets sbr->m[1] up to 63 with no ≤48 check] → ff_aac_sbr_apply_fixed() → sbr_hf_assemble() → stack OOB write into g_filt_tab[48]/q_filt_tab[48]
- **描述**: In `sbr_hf_assemble()` (aacsbr_fixed.c line 531), two fixed-size stack arrays `SoftFloat g_filt_tab[48]` and `SoftFloat q_filt_tab[48]` are allocated. The loop at line 538 iterates `for (m = 0; m < m_max; m++)` where `m_max = sbr->m[1]`. The value `sbr->m[1]` is derived from the bitstream as `f_tablehigh[n[1]] - f_tablehigh[0]`, and the only validation in `sbr_make_f_derived()` is `kx[1] + m[1] <= 64` (template.c:568) — no check that `m[1] <= 48` exists. At a SBR sample rate of 192 kHz, `k[0]` computes to `start_min(=3) + sbr_offset[5][bs_start_freq=0](=-2) = 1`, so `kx[1] = 1` is reachable, allowing `m[1]` up to 63. With `m_max = 63`, the writes `g_filt[m].mant = g_filt[m].exp = 0` at line 540-541 write 15 × sizeof(SoftFloat) = 120 bytes past the end of the 48-element stack array, corrupting adjacent stack frames and the return address.
- **触发条件**: 构造一个 AAC-HE (SBR) 音频文件或 M4A/MP4 容器，内嵌 SBR extension element：将 sample rate 设为 96 kHz（SBR 工作在 192 kHz），bs_start_freq=0, bs_xover_band=0，bs_stop_freq 设为使 k[2] 接近 64，并将 bs_smoothing_mode=0（使 h_SL=4 以进入 g_filt_tab 代码路径），bs_num_env > 0 且 e != e_a。
- **安全影响**: 攻击者可覆盖栈上返回地址及局部变量，在开启 SBR 的 AAC 解码器上实现任意代码执行（RCE），影响任何调用 ffmpeg/ffplay/libavcodec 解码 HE-AAC 流的程序。

## VULN: Heap Buffer Overflow in sbr_gain_calc via Unchecked m[1] > 48
- **漏洞类别**: memory-safety
- **函数**: sbr_gain_calc()
- **行号**: 411-480 (aacsbr_fixed.c); additionally sbr_env_estimate() / sbr_mapping() in aacsbr_template.c:1639-1682 / 1582-1616
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted AAC media file with embedded SBR extension
- **外部触发路径**: ffmpeg -i <crafted_aac_or_mp4> -f null - → avformat_open_input() → ff_aac_sbr_decode_extension_fixed() → sbr_reset() → sbr_make_f_derived() [sets sbr->m[1] > 48] → ff_aac_sbr_apply_fixed() → sbr_dequant() → sbr_env_estimate() / sbr_gain_calc() → OOB write into heap-allocated SpectralBandReplication fields
- **描述**: `sbr_gain_calc()` (aacsbr_fixed.c lines 411-480) writes to `sbr->gain[e][m]`, `sbr->q_m[e][m]`, `sbr->s_m[e][m]` where `m < sbr->f_tablelim[k+1] - sbr->kx[1]` ≤ `sbr->m[1]`. These fields are declared as `AAC_FLOAT gain[8][48]`, `q_m[8][48]`, `s_m[8][48]` in `SpectralBandReplication` (sbr.h). When `m[1]` exceeds 48 (possible when `kx[1] < 16`; with 192 kHz SBR and `bs_start_freq=0`, `kx[1] = 1` and `m[1]` up to 63), writes at `m = 48..62` overflow into adjacent struct fields: `qmf_filter_scratch[5][64]`, followed by function pointers `mdct_ana`, `mdct_ana_fn`, `mdct`, `mdct_fn` (all in the heap-allocated `ExtChannelElement`). The same unchecked `m[1]` also causes OOB writes in `sbr_env_estimate()` into `e_curr[8][48]` (template.c:1642) and `e_origmapped[8][48]` / `q_mapped[8][48]` in `sbr_mapping()` (template.c:1584/1590). No check of the form `m[1] <= 48` or `m[1] <= MAX_QMF_SUBBANDS-kx` exists anywhere in the validation path.
- **触发条件**: 同上：构造 HE-AAC 文件，在 96 kHz 基础采样率（SBR 192 kHz）下设 bs_start_freq=0（sbr_offset=-2 → k[0]=1 → kx[1]=1），选择 bs_stop_freq 使 k[2] 趋近 64（m[1] 最大约 63），正常解码时触发 sbr_gain_calc/sbr_env_estimate 的多处 OOB 写。
- **安全影响**: 堆内 `ExtChannelElement` 结构中的函数指针 `mdct_ana_fn`/`mdct_fn` 被攻击者控制的数据覆盖；在下一次调用 `sbr->mdct_fn(...)` 时劫持 PC，可实现远程代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
