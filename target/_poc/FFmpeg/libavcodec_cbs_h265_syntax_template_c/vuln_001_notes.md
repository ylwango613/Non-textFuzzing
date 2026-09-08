# VULN-001: Off-by-One OOB Heap Write in HEVC CBS sei_pic_timing

## Vulnerability Summary

**File**: `libavcodec/cbs_h265_syntax_template.c`, lines 1997–2009  
**CWE**: CWE-787 (Out-of-bounds Write)  
**Array**: `H265RawSEIPicTiming.num_nalus_in_du_minus1[HEVC_MAX_SLICE_SEGMENTS]`  
         size = 600 elements (indices 0–599)  
**OOB access**: index 600 when `num_decoding_units_minus1 = 600`

## Root Cause

```c
// Line 1997
ue(num_decoding_units_minus1, 0, HEVC_MAX_SLICE_SEGMENTS);  // max = 600

// Lines 2004–2006
for (i = 0; i <= current->num_decoding_units_minus1; i++) {
    ues(num_nalus_in_du_minus1[i],            // OOB at i=600
        0, HEVC_MAX_SLICE_SEGMENTS, 1, i);
```

When `num_decoding_units_minus1 = 600`, the loop runs `i = 0..600` (601 iterations),
writing to `num_nalus_in_du_minus1[600]`. The array has only 600 elements (0–599).

## Trigger Conditions

1. **SPS VUI HRD must have**:
   - `vui_parameters_present_flag = 1`
   - `vui_timing_info_present_flag = 1`
   - `vui_hrd_parameters_present_flag = 1`
   - `nal_hrd_parameters_present_flag = 1` (or vcl)
   - `sub_pic_hrd_params_present_flag = 1`
   - `sub_pic_cpb_params_in_pic_timing_sei_flag = 1`

2. **Prefix SEI NAL must contain pic_timing** (payloadType=1) with:
   - `num_decoding_units_minus1 = 600` (UE-Golomb: 19 bits)

## PoC Approach

`vuln_001_gen.py` constructs a minimal HEVC Annex-B bitstream containing:

1. **VPS** (NAL type 32): Minimal VPS referencing layer 0, no timing info.

2. **SPS** (NAL type 33): Minimal SPS with VUI timing parameters:
   - `vui_timing_info_present_flag = 1`
   - `vui_hrd_parameters_present_flag = 1`
   - `sub_pic_hrd_params_present_flag = 1`
   - `sub_pic_cpb_params_in_pic_timing_sei_flag = 1`
   - All length fields set to 0 (1-bit fields in SEI)

3. **PPS** (NAL type 34): Minimal PPS referencing SPS 0.

4. **Prefix SEI** (NAL type 39): Contains pic_timing SEI with:
   - `num_decoding_units_minus1 = 600`
   - `du_common_cpb_removal_delay_flag = 1`
   - 601 × `num_nalus_in_du_minus1[i] = 0` entries

## Trigger Path

```
ffmpeg -i crafted.h265 -bsf:v trace_headers -f null -
  → ff_cbs_read_packet()
  → cbs_h265_read_nal_unit()           [reads VPS, SPS, PPS, SEI]
  → FUNC_H265(sei_pic_timing)()         [parsing Prefix SEI]
  → loop i=0..600:
      ues(num_nalus_in_du_minus1[i])   [OOB WRITE at i=600]
```

## Expected Behavior

With ASAN enabled: heap-buffer-overflow write at `num_nalus_in_du_minus1[600]`.  
The `H265RawSEIPicTiming` struct is heap-allocated; writing beyond index 599
corrupts adjacent heap data. ASAN should report a `heap-buffer-overflow`.

## UE-Golomb Encoding of 600

```
600 + 1 = 601 = 0b1001011001  (10 bits)
Prefix zeros: 9
Encoded: 0000000001 001011001  (19 bits total)
```
