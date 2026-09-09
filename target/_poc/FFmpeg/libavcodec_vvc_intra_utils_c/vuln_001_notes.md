# VULN-001: VVC intra_pred_angle_derive OOB Read — PoC Skipped

## Vulnerability Summary

**File**: `libavcodec/vvc/intra_utils.c`, function `ff_vvc_intra_pred_angle_derive()`
**CWE**: CWE-125 (Out-of-bounds Read)

```c
int ff_vvc_intra_pred_angle_derive(const int pred_mode)
{
    static const int angles[] = {   // 31 elements, indices 0-30
          0,   1,   2,   3,   4,   6,   8,  10,  12,  14,  16,  18,  20,  23,  26, 29,
         32,  35,  39,  45,  51,  57,  64,  73,  86, 102, 128, 171, 256, 341, 512
    };
    int sign = 1, idx, intra_pred_angle;
    if (pred_mode > INTRA_DIAG) {        // INTRA_DIAG = 34
        idx = pred_mode - INTRA_VERT;
    } else if (pred_mode > 0) {
        idx = INTRA_HORZ - pred_mode;
    } else {
        idx = INTRA_HORZ - 2 - pred_mode;   // <-- vulnerable branch
    }
    // ...
    intra_pred_angle = sign * angles[idx];  // <-- OOB when idx >= 31
```

For `pred_mode = -15`: `idx = 18 - 2 - (-15) = 31` → `angles[31]` (OOB, array size = 31)
For `pred_mode = -16`: `idx = 18 - 2 - (-16) = 32` → `angles[32]` (OOB)

## Trigger Conditions

Negative intra prediction modes (-15, -16) arise from `ff_vvc_wide_angle_mode_mapping()`:

```c
if (nh > nw && pred_mode_intra <= 66 && pred_mode_intra > min)
    pred_mode_intra -= 67;
```

Where `min = 60 - 2 * wh_ratio` and `wh_ratio = FFABS(log2(nw) - log2(nh))`.

For wh_ratio=5 (CU dimensions 4x128: log2(128)-log2(4)=7-2=5):
- `min = 60 - 10 = 50`
- Mode 51 becomes 51 - 67 = **-16** (idx=32, OOB)
- Mode 52 becomes 52 - 67 = **-15** (idx=31, OOB)

Additionally, for `ff_vvc_wide_angle_mode_mapping()` to use `cu->cb_width/cb_height`
instead of the TB dimensions, the CU must have `isp_split_type != ISP_NO_SPLIT` —
i.e., ISP (Intra Sub-Partitions) must be active on that coding unit.

Required configuration summary:
1. SPS: `sps_isp_enabled_flag = 1`, CTU size >= 128, depth params allowing 4x128 CU
2. CU: ISP_HOR_SPLIT, dimensions 4x128 (width=4, height=128)
3. Intra luma prediction mode: 51 or 52 (CABAC-decoded)

## Why This PoC Is Skipped

### 1. CABAC Entropy Coding Cannot Be Manually Crafted

VVC uses CABAC (Context-Adaptive Binary Arithmetic Coding) for all slice data
including intra prediction modes. The intra luma prediction mode for a CU is
encoded through multiple CABAC syntax elements:

- `intra_luma_ref_idx` (multi-symbol CABAC)
- `intra_luma_mpm_flag` (1-bit CABAC)
- If MPM: `intra_luma_mpm_idx` (truncated Rice CABAC)
- If non-MPM: `intra_luma_pred_mode` (5-bit fixed, but within CABAC stream)

The probability contexts for each of these elements depend on:
- Previously decoded syntax elements (neighboring CU modes, partition depth, etc.)
- QP-derived initialization values
- Running CABAC state (ivlCurrRange, ivlOffset) that changes with every decoded bit

Without running the actual CABAC arithmetic, there is no deterministic way to
construct raw byte sequences that will decode to specific intra mode values.

### 2. Complex Prerequisite Partition Tree

A 4x128 CU with ISP requires:
- CTU size of at least 128x128 (sps_log2_ctu_size_minus5 = 2)
- Quadtree and multi-type-tree splits producing a 4x128 leaf node
- ISP must then be signaled for that CU

The entire partition tree from CTU root to the 4x128 leaf is also CABAC-coded
(split flags, split modes). Crafting this tree by injecting arbitrary bytes
will almost certainly produce a parse error before reaching the intra mode.

### 3. Empirical Evidence from Analogous PoC

A closely analogous PoC attempt was made for a different VVC CABAC vulnerability
(libavcodec/vvc/cabac.c) using the same approach: crafting a syntactically valid
SPS + PPS + slice header, then injecting crafted CABAC bytes. The result was:

    ffmpeg: "frame 0, P(0,0) failed" ← CABAC decode error at first CTU
    No ASAN report generated (never reached the vulnerable code path)

That PoC concluded UNVERIFIED because the CABAC payload could not be made to
produce the required partition/mode combination without an actual encoder.

The current vulnerability has the same fundamental obstacle, with the additional
requirement of a specific 4:128 CU aspect ratio, making it even harder to reach.

### 4. Alternative Approaches Also Infeasible

- **Fuzzing with existing VVC test vectors**: No VVC test files with the required
  4x128 ISP CU configuration were found in the repository or target directory.
- **Using a VVC encoder**: Would require building/using VTM (VVC Test Model) or
  similar encoder, compile it with specific settings to produce 4x128 ISP CUs
  with modes 51/52 — this is outside the scope of a Python-only PoC generator.
- **Binary patching of an existing VVC file**: No suitable base file exists.

## Vulnerability Reality Assessment

The vulnerability is real code: `angles[31]` and `angles[32]` are genuine
out-of-bounds reads. On an ASAN build, these would trigger a READ error.
However, reaching this code path requires:

1. A conformant VVC encoder producing ISP CUs with extreme aspect ratios (4:128)
2. Specific intra modes (51/52) for those CUs

In practice this means the vulnerability is most exploitable via:
- A real VVC encoder configured to produce such CUs (VTM reference software)
- Corrupted or specially constructed VVC streams from a modified encoder

## Status: SKIPPED

No PoC binary file generated. A PoC would require either a VVC encoder
(e.g., VTM) or a fuzzer capable of generating semantically valid VVC content
with specific intra mode assignments — neither of which is achievable through
Python struct/bytes manipulation alone.
