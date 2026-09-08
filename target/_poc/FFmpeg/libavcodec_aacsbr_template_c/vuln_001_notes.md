# VULN 001 - PoC Analysis Notes

## Vulnerability Description

**Title**: Heap OOB Write via Unchecked n_master in sbr_make_f_master  
**File**: libavcodec/aacsbr_template.c (lines 473-479)  
**Function**: sbr_make_f_master()

The `f_master[]` array in the `SpectralBandReplication` struct is declared as
`uint16_t f_master[49]` (sbr.h:182). The function `check_n_master()` validates that
`n_master > 0` and `bs_xover_band < n_master`, but does NOT check whether
`n_master <= 49` (the array size). If `n_master` could reach 60, the final `memcpy`
at lines 477-480 would write 60 entries to a 49-element array, overflowing by
11 entries (22 bytes).

## PoC Approach

The PoC crafts an ADTS file with:
- **ADTS sample rate**: 96000 Hz (sampling_frequency_index=0)
- **SBR sample rate**: 192000 Hz (2 × core sample rate, as set by FFmpeg at
  `sbr->sample_rate = 2 * ac->oc[1].m4ac.sample_rate`)
- **Payload**: minimal SCE element (max_sfb=0, no spectral data) followed by a
  TYPE_FIL element containing EXT_SBR_DATA with crafted header bits

**Crafted SBR header parameters**:
- `bs_start_freq = 0` → k0 = start_min + sbr_offset[5][0] = 3 + (−2) = **1**
- `bs_stop_freq = 9` → k2 = stop_min + Σ(9 smallest stop_dk) = 7 + 25 = **32**
- `bs_freq_scale = 1` → half_bands = 6, two_regions=True (49×32 > 110×1), k1=2
- `bs_alter_scale = 0` → invwarp = 1.0

**Theoretical n_master calculation**:
- `num_bands_0 = round(6 × log₂(2/1)) × 2 = round(6) × 2 = 12`
- `num_bands_1 = round(6 × log₂(32/2)) × 2 = round(6 × 4) × 2 = 48`
- `n_master = 12 + 48 = 60 > 49` → OOB write (theoretical)

## Actual Observed Behavior

When run through the ASAN-instrumented ffmpeg binary, FFmpeg outputs:

```
[aac @ ...] Invalid vDk0[1]: 0
[aac @ ...] SBR reset failed. Switching SBR to pure upsampling mode.
```

**No ASAN heap-buffer-overflow is triggered.** The decoder gracefully disables SBR.

## Root Cause Analysis of Why Trigger Fails

### The Blocking Guard: make_bands Validity Check

Before the final `memcpy` in `sbr_make_f_master()`, there is a validity check
(aacsbr_template.c ~lines 419-426):

```c
vk0[0] = sbr->k[0];
for (k = 1; k <= num_bands_0; k++) {
    if (vk0[k] <= 0) {  // Check: all band sizes must be positive
        av_log(ac->avctx, AV_LOG_ERROR, "Invalid vDk0[%d]: %d\n", k, vk0[k]);
        return -1;       // Returns BEFORE the OOB memcpy!
    }
    vk0[k] += vk0[k-1];
}
```

This check fires when `make_bands(vk0+1, k0=1, k1=2, num_bands=12)` produces
zero-width frequency bands.

### Mathematical Proof of Failure

`make_bands(start=1, stop=2, num_bands=12)` uses geometric distribution:
- base = 2^(1/12) ≈ 1.05946
- First product: 1.0 × 1.05946 = 1.05946 → `lrintf(1.05946) = 1`
- First band width = 1 − 1 = **0** (zero-width!)

This is mathematically inevitable: for k0=1 and k1=2, ANY number of bands ≥ 2
causes the first lrintf step to equal k0, producing a zero-width band that
triggers the guard.

### Why Valid Parameters Cannot Produce n_master > 49

For the OOB `memcpy` to be reached with n_master > 49, the required parameters
violate mathematical constraints:

**Constraint 1 - make_bands validity** (no zero bands in region 0):  
For `make_bands(k0, 2×k0, 12)` to produce all-positive bands:
`k0 × (2^(1/12) − 1) ≥ 0.5` → **k0 ≥ 14**

**Constraint 2 - Max QMF subbands** (for SBR rate ≥ 48000 Hz):  
`k2 − k0 ≤ 32` → `k2 ≤ k0 + 32`

**Constraint 3 - n_master requirement**:  
`n_master = 12 + num_bands_1 > 49` → `num_bands_1 > 37`  
`round(6 × log₂(k2/k1)) × 2 > 37` → `k2/k1 > 8.5` → `k2 > 8.5 × 2 × k0 = 17 × k0`

**Contradiction**: With k0 ≥ 14 and k2 ≤ k0 + 32:
`17 × k0 < k2 ≤ k0 + 32` → `16 × k0 < 32` → **k0 < 2**

But k0 ≥ 14 (from Constraint 1) and k0 < 2 (from combined constraints) are
irreconcilable. **The vulnerability cannot be triggered with valid ADTS parameters.**

For lower SBR rates (≤ 32000 Hz) where max_qmf=48, the required k0 for 
valid make_bands is achievable, but k2 is still too small relative to k1=2×k0
to produce num_bands_1 > 37. The constraints prevent the OOB write.

## Possible Alternative Scenarios

1. **USAC/MP4 container**: The USAC decoder path (`ff_aac_sbr_decode_usac_data`)
   sets SBR parameters differently via `copy_usac_default_header()`. An M4A/MP4
   file with explicit `SBRConfig` in the `AudioSpecificConfig` might allow setting
   the SBR sample rate independently, potentially reaching the vulnerable code path.

2. **USE_FIXED code path**: The fixed-point computation in `aacsbr_fixed.c` uses
   integer arithmetic that might produce different (incorrect) results for k0=1,
   k1=2 due to the fixed-log computation with zero input. However, the desktop
   build uses floating-point by default.

3. **Historical version**: The `if (vk0[k] <= 0) return -1` guard may have been
   absent in an earlier version, where the vulnerability was fully exploitable.
   The check may have been added as a mitigation without explicitly noting the
   root cause in `check_n_master()`.

## Status Determination

**UNVERIFIED** - The PoC correctly reaches the `sbr_make_f_master()` code path
(confirmed by the "Invalid vDk0" log message), but the earlier band-width validity
check prevents the OOB `memcpy` from executing. ASAN does not report any
heap-buffer-overflow. The described vulnerability trigger requires conditions
(k0=1 with 12 valid frequency bands) that are mathematically impossible with
standard ADTS input.

## Files

- `vuln_001_gen.py` - PoC bitstream generator
- `vuln_001_run.sh` - Execution script
- `vuln_001_input.aac` - Generated malformed ADTS file
- `vuln_001_result.txt` - Full FFmpeg output with annotations
