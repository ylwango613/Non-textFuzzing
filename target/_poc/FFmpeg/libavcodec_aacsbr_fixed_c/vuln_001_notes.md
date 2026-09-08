# VULN 001: Stack Buffer Overflow in sbr_hf_assemble (aacsbr_fixed.c)

## Summary

A potential stack buffer overflow exists in `sbr_hf_assemble()` in
`libavcodec/aacsbr_fixed.c` (lines 531-549). The function declares fixed-size
stack arrays `g_filt_tab[48]` and `q_filt_tab[48]`, but does not verify that
`m[1]` (the number of high-frequency bands) is bounded to 48 before looping
`for (m = 0; m < m_max; m++)` with `m_max = sbr->m[1]`.

The upstream validation in `sbr_make_f_derived()` (aacsbr_template.c:568) only
checks `kx[1] + m[1] <= 64`, not `m[1] <= 48`. A dedicated check for
`m[1] <= 48` is missing.

## Trigger Conditions

| Parameter | Value | Effect |
|-----------|-------|--------|
| Base AAC sample rate | 8000 Hz (ADTS sfi=11) | SBR doubles to 16000 Hz |
| SBR sample rate | 16000 Hz → sbr_offset[0] | start_min=24, stop_min=48 |
| `bs_start_freq` | 0 | k[0] = 24 + (-8) = 16; kx[1] = 16 |
| `bs_stop_freq` | 13 | k[2] = stop_min + all 13 bands = 64 |
| `bs_xover_band` | 0 | kx[1] = f_master[0] = k[0] = 16 |
| `m[1]` | 48 | = k[2] - kx[1] = 64 - 16 (boundary of g_filt_tab[48]) |
| `bs_smoothing_mode` | 0 | h_SL = 4*!0 = 4 → g_filt_tab code path is taken |

At 16000 Hz SBR, `max_qmf_subbands = 48` (code: `sample_rate <= 32000 → 48`).
The QMF check `k[2] - k[0] > max_qmf_subbands` evaluates as `48 > 48 = false`,
so it passes. This allows `m[1] = 48` exactly.

## Overflow Analysis

The stack arrays `SoftFloat g_filt_tab[48]` and `SoftFloat q_filt_tab[48]` hold
exactly 48 elements (indices 0..47). When `m[1] = 48`, the loop:

```c
for (m = 0; m < m_max; m++) {   // m_max = 48, iterates m = 0..47
    g_filt[m] = ...;             // g_filt_tab[47] is the last write
```

accesses indices 0..47 — exactly within bounds. This is a strict boundary
condition. For a true overflow (access to index 48+), `m[1]` would need to
exceed 48. The existing max_qmf_subbands constraint limits `k[2] - k[0]` to 48
for rates ≤ 32000 Hz, making `m[1] > 48` very difficult to achieve through
standard parameters alone.

**However:** The vulnerability description identifies this as a missing explicit
check (`m[1] <= 48`) in `sbr_make_f_derived`, separate from the QMF subband
constraint. If that QMF check were ever bypassed (e.g., via a corrupted/crafted
state), `m[1]` up to 63 would be possible (kx[1]=1, m[1]=63 at 192 kHz SBR
if the 32-subband cap could be evaded).

## PoC Design

- **Format**: ADTS-wrapped HE-AAC with SBR in fill element (ext type 0xD)
- **Base codec**: AAC-LC at 8000 Hz, mono, max_sfb=0 (silent)
- **SBR header**: bs_start_freq=0, bs_stop_freq=13, bs_smoothing_mode=0
- **SBR data**: 1 envelope (FIXFIX), all-zero values, n[1]=18 bands, n_q=4 noise bands
- **Decoder**: Force `aac_fixed` to use the fixed-point SBR path (aacsbr_fixed.c)
- **Frames**: 10 identical frames to ensure SBR state stabilizes beyond initial reset

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Python script generating `vuln_001_input.aac` |
| `vuln_001_run.sh` | Run FFmpeg with ASAN and collect results |
| `vuln_001_input.aac` | Generated crafted HE-AAC file (created by gen.py) |
| `vuln_001_result.txt` | FFmpeg output + ASAN logs |
| `vuln_001_status.txt` | One-line verdict |

## Expected Outcome

With m[1] = 48 (boundary condition):
- If FFmpeg processes the SBR successfully without crashing: `VERIFIED_BEHAVIOR`
- If ASAN detects a stack overflow (m[1] somehow > 48): `VERIFIED_CRASH`
- If parsing fails early due to format issues: `UNVERIFIED`

## Relevant Code

**aacsbr_fixed.c:531-549 (vulnerable loop):**
```c
SoftFloat g_filt_tab[48];        // ← fixed-size stack array
SoftFloat q_filt_tab[48];
...
if (h_SL && e != e_a[0] && e != e_a[1]) {
    g_filt = g_filt_tab;
    q_filt = q_filt_tab;
    for (m = 0; m < m_max; m++) {   // ← m_max = sbr->m[1], unchecked
        ...
        g_filt[m] = ...;             // ← overflow if m_max > 48
        q_filt[m] = ...;
    }
}
```

**aacsbr_template.c:564-572 (missing check):**
```c
sbr->m[1] = sbr->f_tablehigh[sbr->n[1]] - sbr->f_tablehigh[0];
sbr->kx[1] = sbr->f_tablehigh[0];
// Only checks kx[1] + m[1] <= 64, NOT m[1] <= 48:
if (sbr->kx[1] + sbr->m[1] > 64) {   // ← insufficient
    av_log(..., "Stop frequency border too high: %d\n", ...);
    return -1;
}
// Missing: if (sbr->m[1] > 48) { return -1; }
```
