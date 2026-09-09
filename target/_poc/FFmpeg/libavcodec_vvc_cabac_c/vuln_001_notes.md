# VULN-001 PoC Notes: OOB Read via Negative Scan-Table Index in init_residual_coding

## Vulnerability

**File**: `libavcodec/vvc/cabac.c`, lines 2086-2128  
**Function**: `init_residual_coding()`  
**CWE**: CWE-125 (Out-of-bounds Read) / CWE-787 (Out-of-bounds Write)

### Vulnerable Code

```c
static void init_residual_coding(const VVCLocalContext *lc, ResidualCoding *rc,
    const int log2_zo_tb_width, const int log2_zo_tb_height,
    TransformBlock *tb)
{
    int log2_sb_w = (FFMIN(log2_zo_tb_width, log2_zo_tb_height) < 2 ? 1 : 2);
    int log2_sb_h = log2_sb_w;

    if (log2_zo_tb_width + log2_zo_tb_height > 3) {   // (A)
        if (log2_zo_tb_width < 2) {
            log2_sb_w = log2_zo_tb_width;              // corrects to 0
            log2_sb_h = 4 - log2_sb_w;
        }
        ...
    }
    ...
    // Line 2112 - OOB when log2_zo_tb_width=0 and correction not applied:
    rc->sb_scan_x_off = ff_vvc_diag_scan_x[log2_zo_tb_width - log2_sb_w]  // index = -1 !
                                           [log2_zo_tb_height - log2_sb_h];
```

When `log2_zo_tb_width = 0` and `log2_zo_tb_height <= 3`:
- `FFMIN(0, h) < 2` → `log2_sb_w = 1`
- `0 + h <= 3` → condition (A) is **not entered**
- `log2_sb_w` stays at **1**
- Array index: `ff_vvc_diag_scan_x[0 - 1][...]` = `ff_vvc_diag_scan_x[-1][...]` → **OOB**

For `(log2_zo_tb_width=0, log2_zo_tb_height=1)`:
- Line 2106: `1 << (0+1-2) = 1 << -1` → undefined behavior (signed left-shift by negative)

## PoC Approach

### File Generated
`vuln_001_input.h266` — a minimal VVC (H.266) Annex-B bitstream containing:
- SPS with `sps_isp_enabled_flag=1` (enables ISP mode)
- PPS with `pps_no_pic_partition_flag=1` (simplified partitioning)
- IDR slice with embedded picture header + crafted CABAC payload

### Code Path Targeted
```
ffmpeg -i vuln_001_input.h266 -f null -
  → VVC demux → avcodec_send_packet
  → ff_vvc_decode_frame → vvc_decode_slice
  → ff_vvc_residual_coding → hls_residual_coding
  → init_residual_coding (vulnerable function)
```

### ISP Mode Analysis

The vulnerability description states the trigger requires:
- `log2_tb_width = 0` (1-pixel-wide TB)
- `log2_tb_height <= 3` (≤8-pixel-tall TB)

**Reachability with valid VVC syntax**:

In VVC, `log2_tb_width = 0` (width=1) is produced by ISP vertical split
(`ISP_VER_SPLIT`) when `trafo_width = cb_width / num_intra_subpartitions = 1`.

This requires `cb_width = 4` and `num_intra_subpartitions = 4` (the maximum).
`get_num_intra_subpartitions()` returns 4 only when the block is NOT the special
`(4×8)` or `(8×4)` case, meaning `cb_height >= 16`.

For `cb_height = 16, cb_width = 4, ISP_VER_SPLIT`:
- `num_intra_subpartitions = 4`
- Each sub-TU: `trafo_width = 1`, `trafo_height = 16`
- TB dimensions: `1 × 16` → `log2_tb_width=0, log2_tb_height=4`

But with `log2_zo_tb_width=0, log2_zo_tb_height=4`:
- `0 + 4 = 4 > 3` → **correction branch IS taken** → `log2_sb_w = 0` → no OOB

**Conclusion**: The exact trigger (`log2_tb_width=0, log2_tb_height<=3`) is not
achievable through standard valid VVC ISP syntax. The closest valid configuration
(1×16 from 4×16 ISP_VER_SPLIT) avoids the OOB due to the correction branch.

The vulnerability exists as a coding defect that would be triggered by:
1. A non-conformant encoder that produces 1×{2,4,8} transform blocks
2. A bitstream with corrupted partition tree data causing unexpected TB dimensions
3. Potentially via future VVC extensions or implementation divergences

### What the PoC Actually Tests

The crafted bitstream attempts to exercise:
1. VVC SPS parsing with ISP flag enabled
2. VVC PPS parsing (minimal)  
3. VVC IDR slice decoding (CABAC engine initialization)
4. The ISP-related code paths when the decoder processes the CTU

With the random/crafted CABAC payload, the decoder may:
- Hit various error paths during partition tree decoding
- Reach the ISP code path with the 1×16 configuration
- Exhibit other anomalous behavior from the malformed CABAC stream

## Expected Results

Without the exact trigger condition being met:
- **UNVERIFIED**: No ASAN crash from the specific OOB at `ff_vvc_diag_scan_x[-1]`
- **BEHAVIOR**: Decoder error messages from malformed bitstream

The vulnerability is a **code-level defect** that requires either a non-standard
encoder or a malformed bitstream with specific partition tree corruption to trigger.

## References

- `libavcodec/vvc/cabac.c` lines 2086-2128 (init_residual_coding)
- `libavcodec/vvc/ctu.c` lines 465-479 (ISP transform tree splitting)
- `libavcodec/vvc/ctu.c` lines 625-632 (get_num_intra_subpartitions)
- `libavcodec/vvc/data.h` line 29 (ff_vvc_diag_scan_x declaration)
