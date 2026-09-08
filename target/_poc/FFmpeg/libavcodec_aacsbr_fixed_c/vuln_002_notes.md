# VULN 002: Heap Buffer Overflow in sbr_gain_calc via Unchecked m[1] > 48

## Vulnerability Summary

- **File**: `libavcodec/aacsbr_fixed.c` (sbr_gain_calc), `libavcodec/aacsbr_template.c` (sbr_env_estimate, sbr_mapping)
- **Type**: Heap Buffer Overflow (CWE-122)
- **Trigger**: HE-AAC SBR bitstream with `m[1] > 48`, causing out-of-bounds writes into heap arrays

## Root Cause

The SpectralBandReplication struct contains fixed-size arrays:
```c
AAC_FLOAT  e_curr[8][48];
AAC_FLOAT  q_m[8][48];
AAC_FLOAT  s_m[8][48];
AAC_FLOAT  gain[8][48];
// Immediately after:
INTFLOAT   qmf_filter_scratch[5][64];
AVTXContext *mdct_ana;
av_tx_fn    mdct_ana_fn;
AVTXContext *mdct;
av_tx_fn    mdct_fn;
```

`sbr_gain_calc()` iterates `for (m = 0; m < sbr->m[1]; m++)` and writes to
`sbr->gain[e][m]`, `sbr->q_m[e][m]`, `sbr->s_m[e][m]` (and analogously in
`sbr_env_estimate` for `e_curr[e][m]`). When `m[1] > 48`, index `m >= 48` is
out of bounds and corrupts the adjacent `qmf_filter_scratch` then the
`mdct_ana_fn`/`mdct_fn` function pointers.

Those function pointers are subsequently called by the QMF synthesis path,
providing a code-execution primitive.

## Trigger Parameters

For SBR sample rate = 16000 Hz (HE-AAC core at 8000 Hz):

| Parameter | Value | Effect |
|---|---|---|
| `bs_start_freq` | 0 | `k[0]` = `kx[1]` = 16 |
| `bs_stop_freq` | 13 | `k[2]` = 64 (capped) |
| `bs_xover_band` | 0 | High-freq table starts at `k[0]` |
| `bs_freq_scale` | 0 | Linear bands, `n_master` = 24 |
| `bs_alter_scale` | 1 | `dk` = 2 |
| → `m[1]` | **48** | Boundary value (arrays are size 48) |

Without the `max_qmf_subbands` guard in `sbr_make_f_master`, `m[1]` can reach
63 when `kx[1]` = 1 (a valid configuration satisfying `kx[1]+m[1] ≤ 64`),
which overflows by 15 elements into function-pointer fields.

## PoC File

- **Input**: `vuln_002_input.m4a` — crafted HE-AAC file (AOT=5, core=8kHz,
  SBR=16kHz, mono) with SBR fill elements that maximize `m[1]`.
- **AudioSpecificConfig**: `2D 8C 08 00` (AOT=5, extSmpFreq=16kHz, core AOT=2)
- **SBR FILL payload**: SBR header with `bs_start_freq=0`, `bs_stop_freq=13`,
  `bs_freq_scale=0`; valid silence envelope/noise coded with all-zero VLC
  deltas (Huffman delta=0 is the shortest code for these tables).

## Observed Behavior

The PoC exercises:
1. `sbr_make_f_master` → `m[1]` = 48 (at the array boundary)
2. `sbr_make_f_derived` → `kx[1]` = 16, `n[1]` = 24, `n_q` = 4
3. `sbr_lf_gen`, `sbr_hf_gen`, `sbr_mapping`, `sbr_env_estimate`
4. **`sbr_gain_calc`** → accesses `gain[e][0..47]` (boundary, no OOB with current guard)

The current code has a `max_qmf_subbands = 48` guard that limits `k[2]-k[0]`
to 48, keeping `m[1]` at exactly 48 (the last valid index is 47). A version
missing this guard, or with a larger limit, would trigger the OOB.

## Attack Vector

```
ffmpeg -i <crafted_heaac.m4a> -f null -
```

A malicious HE-AAC stream embedded in MP4, ADTS, or LATM can be delivered
via any audio/video container. No user interaction beyond opening the file is
required.
