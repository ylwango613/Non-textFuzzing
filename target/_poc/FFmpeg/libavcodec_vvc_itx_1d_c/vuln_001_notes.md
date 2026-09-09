# VULN_001: Stack Buffer Overflow in matrix_mul() via DCT8/DST7 32-point Transform

## Vulnerability Summary

- **File**: `libavcodec/vvc/itx_1d.c`, lines 644–661
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **Function**: `matrix_mul()`

## Vulnerable Code

```c
static void matrix_mul(int *coeffs, const ptrdiff_t stride, const int8_t* matrix,
                        const int size, const size_t nz)
{
    // comment says "coeffs > 16 are zero out" — but this is only true for SBT path
    int tmp[16];                        // FIXED 16-element buffer
    for (int i = 0; i < nz; i++)
        tmp[i] = coeffs[i * stride];   // OOB write when nz > 16
    ...
}
```

When `nz > 16`, writing to `tmp[16]` through `tmp[nz-1]` overflows the stack buffer.

## Trigger Conditions

1. `sps_mts_enabled_flag = 1` AND `sps_explicit_mts_intra_enabled_flag = 1`
2. `sps_sbt_enabled_flag = 0` — ensures the non-SBT path where `log2_zo_tb_width = FFMIN(5,5) = 5` (no zero-out protection)
3. 32×32 intra CU with `mts_idx = 1` (DST7) or `mts_idx = 2` (DCT8)
4. `tb->max_scan_x >= 16` → `nzw = max_scan_x + 1 > 16`
5. `matrix_mul()` called via `itx_2d()` in `intra.c`

## Gating Mechanism (Potential Mitigation)

The decoder has a flag `mts_zero_out_sig_coeff_flag` initialized to 1 at the start of each CU. In `cabac.c` line ~2284:

```c
if (*sb_coded_flag && (xs > 3 || ys > 3) && !tb->c_idx)
    lc->parse.mts_zero_out_sig_coeff_flag = 0;
```

The `mts_idx_decode()` function only decodes `mts_idx` (to DST7/DCT8) if this flag remains 1. However, for `max_scan_x >= 16`, the last significant coefficient sub-block has `xs >= 4`, which clears the flag. This creates a contradiction:

- For overflow: need `max_scan_x >= 16` → clears `mts_zero_out_sig_coeff_flag` → `mts_idx` not decoded → DCT2 used → no overflow
- For DST7/DCT8: need `mts_zero_out_sig_coeff_flag = 1` → coefficients only in first 16 columns → `max_scan_x <= 15` → `nzw <= 16` → no overflow

This suggests the vulnerability may require a code path that bypasses this check, or the check was added as an incomplete mitigation.

## PoC Approach

- **Picture**: 32×32 pixels, single CTU = single 32×32 CU (min_qt_intra=32, max_mtt_depth=0)
- **CABAC data**: 512 bytes of `0x00` → deterministic context decoding
- **SPS**: `sps_mts_enabled_flag=1`, `sps_explicit_mts_intra_enabled_flag=1`, `sps_sbt_enabled_flag=0`
- **PPS**: `pps_no_pic_partition_flag=1`, `pps_init_qp_minus26=0` → QP=26
- **NAL structure**: SPS + PPS + IDR_W_RADL with embedded picture header

## CABAC Analysis (QP=26, init_type=0, I-slice, all-0x00 data)

With `low=512` (CABAC init with 0x00 bytes), `range=0x1FE`:

| Context | init_value | m | n | pre (QP=26) | MPS | Decoded bit |
|---------|-----------|---|---|------------|-----|-------------|
| cu_coded_flag | 6 | -3 | 19 | 89 | 1 | **1** (CU coded) |
| mts_idx[0] | 29 | -1 | 55 | 86 | 1 | **1** (continue) |
| mts_idx[1] | 0 | -4 | 1 | 1 | 0 | **0** (return 1=DST7) |
| last_sig_x ctx=10 | 14 | -3 | 37 | 67 | 1 | 1 |
| last_sig_x ctx=11 | 7 | -4 | 19 | 1 | 0 | 0 (stop at prefix=1) |

Note: For `log2_zo_tb_size=5`, `max=9`, `ctx_offset=10`, `ctx_shift=1`.
With MPS=1 at ctx=10 and MPS=0 at ctx=11 → prefix=1 → value=1.
So `last_sig_coeff_x = 1`, `nzw = 2` — NOT ≥ 16.

The actual `last_sig_coeff_x` decoded is small with all-0x00 CABAC, preventing overflow through the normal path.

## Files

- `vuln_001_gen.py` — Python script generating `vuln_001_input.vvc`
- `vuln_001_run.sh` — Shell script running ASAN-instrumented FFmpeg
- `vuln_001_input.vvc` — Generated VVC bitstream (created at runtime)
- `vuln_001_result.txt` — FFmpeg output (created at runtime)
- `vuln_001_status.txt` — Verification status

## References

- `libavcodec/vvc/itx_1d.c` lines 644–661 (vulnerable function)
- `libavcodec/vvc/cabac.c` line ~2284 (mts_zero_out_sig_coeff_flag gating)
- `libavcodec/vvc/intra.c` lines 432–459 (`itx_2d` calling `matrix_mul`)
- `libavcodec/vvc/ctu.c` lines 2215–2227 (mts_idx decode order)
