# VULN 001 — Off-by-one OOB Write in SEI pic_timing DU loop

## Summary

An off-by-one out-of-bounds write exists in FFmpeg's HEVC Coded Bitstream (CBS)
layer at `libavcodec/cbs_h265_syntax_template.c`, function `FUNC(sei_pic_timing)`.

## Root Cause

`HEVC_MAX_SLICE_SEGMENTS = 600`. The array:

```c
uint16_t num_nalus_in_du_minus1[HEVC_MAX_SLICE_SEGMENTS];  // indices 0..599
```

is declared with exactly 600 elements. The bounds check for `num_decoding_units_minus1`:

```c
ue(num_decoding_units_minus1, 0, HEVC_MAX_SLICE_SEGMENTS);  // allows 0..600
```

allows the maximum value 600. The loop:

```c
for (i = 0; i <= current->num_decoding_units_minus1; i++) {
    ues(num_nalus_in_du_minus1[i], ...);  // writes at i=0..600
```

when `num_decoding_units_minus1 == 600`, writes to index 600 — one past the end
of the array. This is a CWE-787 Out-of-bounds Write.

## PoC Approach

The `vuln_001_gen.py` script constructs a minimal HEVC raw bytestream
(`vuln_001_input.hevc`) with four NAL units:

1. **VPS** (type 32) — minimal, references profile/tier/level for main profile
2. **SPS** (type 33) — enables VUI with timing and HRD parameters:
   - `vui_timing_info_present_flag = 1`
   - `vui_hrd_parameters_present_flag = 1`
   - `nal_hrd_parameters_present_flag = 1`
   - `sub_pic_hrd_params_present_flag = 1`
   - `sub_pic_cpb_params_in_pic_timing_sei_flag = 1`
   - `au_cpb_removal_delay_length_minus1 = 0` (1-bit fields in SEI)
   - `dpb_output_delay_length_minus1 = 0`
   - `du_cpb_removal_delay_increment_length_minus1 = 15` (16-bit DU delay field)
3. **PPS** (type 34) — minimal; parsing PPS activates the SPS
   (`h265->active_sps = sps`), which is required before the SEI can be parsed.
4. **SEI prefix** (type 39) — contains a `pic_timing` message (SEI type 1)
   with `num_decoding_units_minus1 = 600`.

### SEI pic_timing payload layout (80 bytes = 640 bits)

| Field | Size |
|---|---|
| `au_cpb_removal_delay_minus1` (u(1)) | 1 bit |
| `pic_dpb_output_delay` (u(1)) | 1 bit |
| `pic_dpb_output_du_delay` (u(1)) | 1 bit |
| `num_decoding_units_minus1` (ue(600)) | 19 bits |
| `du_common_cpb_removal_delay_flag` | 1 bit |
| `du_common_cpb_removal_delay_increment_minus1` (u(16)) | 16 bits |
| `num_nalus_in_du_minus1[i]` × 601 (ue(0)) | 601 bits |
| **Total** | **640 bits = 80 bytes** |

## Trigger Path

The CBS layer is used by bitstream filters (BSFs), not directly by the native
HEVC decoder. The `trace_headers` BSF explicitly processes each packet through
the CBS framework to trace bitstream fields.

```
ffmpeg -f hevc -i vuln_001_input.hevc -c:v copy -bsf:v trace_headers -f null -
  → raw HEVC demuxer reads NAL units
  → VPS/SPS/PPS go to extradata, processed via CBS during BSF init
  → SEI_PREFIX + IDR form the first packet (flushed when AUD signals next AU)
  → trace_headers BSF calls ff_cbs_read_packet()
  → cbs_h265_read_nal_unit() [HEVC_NAL_SEI_PREFIX]
    → cbs_h265_read_sei()
    → FUNC(sei_pic_timing)()
      → reads num_decoding_units_minus1 = 600
      → loop i=0..600: writes num_nalus_in_du_minus1[600]  ← OOB write
```

The bitstream is structured to make the demuxer produce a proper packet:
- VPS + SPS + PPS → put into extradata during probing
- SEI_PREFIX + IDR_W_RADL → form the first access unit (packet 1)
- AUD (Access Unit Delimiter) → signals start of next AU, flushes packet 1

### Confirmed Output

The UBSan sanitizer (enabled in the test build) reports:

```
[trace_headers] Picture Timing
[trace_headers] num_decoding_units_minus1 = 600
src/libavcodec/cbs_h265_syntax_template.c:2005:17:
  runtime error: index 600 out of bounds for type 'uint16_t [600]'
```

This is line 2005 in the CBS template: `ues(num_nalus_in_du_minus1[i], ...)` when
`i = 600 = HEVC_MAX_SLICE_SEGMENTS`.

## Notes on Sanitizer Behavior

The `H265RawSEIPicTiming` struct contains:

```c
uint16_t num_nalus_in_du_minus1[600];             // indices 0..599
uint32_t du_cpb_removal_delay_increment_minus1[600]; // adjacent
```

The OOB write at `num_nalus_in_du_minus1[600]` falls 2 bytes into
`du_cpb_removal_delay_increment_minus1[0]` (same heap allocation).
ASAN may not crash on this intra-struct write since no redzones exist between
struct fields. However, UBSan's array bounds checking catches it explicitly,
confirming CWE-787 Out-of-bounds Write.
