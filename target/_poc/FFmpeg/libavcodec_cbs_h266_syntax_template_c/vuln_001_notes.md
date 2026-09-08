# VULN 001 Notes: VPS vps_num_ptls_minus1 OOB Analysis

## Vulnerability Claim

**Title**: OOB Heap Write in VPS Parsing via vps_num_ptls_minus1 Exceeding VVC_MAX_PTLS  
**File**: `libavcodec/cbs_h266_syntax_template.c`, lines 788-803, 933-938  
**CWE**: CWE-787 (Out-of-bounds Write)

## Source Code Analysis

### Key Constants (libavcodec/vvc.h)
```c
VVC_MAX_PTLS = 256,
VVC_MAX_TOTAL_NUM_OLSS = 257,
```

### Struct Arrays (libavcodec/cbs_h266.h)
```c
uint8_t  vps_pt_present_flag[VVC_MAX_PTLS];      // size 256, indices 0..255
uint8_t  vps_ptl_max_tid[VVC_MAX_PTLS];           // size 256, indices 0..255
H266RawProfileTierLevel vps_profile_tier_level[VVC_MAX_PTLS]; // size 256, indices 0..255
```

### Parsing Code (cbs_h266_syntax_template.c)
```c
// Line 788:
u(8, vps_num_ptls_minus1, 0, total_num_olss - 1);  // reads EXACTLY 8 bits

// Lines 794-804:
for (i = 0; i <= current->vps_num_ptls_minus1; i++) {
    if (i > 0)
        flags(vps_pt_present_flag[i], 1, i);
    if (!current->vps_default_ptl_dpb_hrd_max_tid_flag)
        us(3, vps_ptl_max_tid[i], ...);
    else
        infer(vps_ptl_max_tid[i], ...);
}

// Lines 933-938:
for (i = 0; i <= current->vps_num_ptls_minus1; i++) {
    CHECK(FUNC(profile_tier_level)(ctx, rw,
                                   current->vps_profile_tier_level + i,
                                   current->vps_pt_present_flag[i],
                                   current->vps_ptl_max_tid[i]));
}
```

## Critical Finding: Vulnerability Cannot Be Triggered As Claimed

The vulnerability report claims `vps_num_ptls_minus1 = 256` causes OOB at index 256.

**This is impossible for the following reason:**

1. `u(8, vps_num_ptls_minus1, ...)` reads **exactly 8 bits** from the bitstream
2. Maximum value of an 8-bit unsigned field = **255**
3. Therefore `vps_num_ptls_minus1` ∈ [0, 255]
4. The loop `for (i = 0; i <= vps_num_ptls_minus1; i++)` iterates i ∈ [0, 255]
5. Array accesses are at indices 0..255
6. Arrays have size `VVC_MAX_PTLS = 256` → valid indices are 0..255
7. **No out-of-bounds write occurs**

The constraint `u(8, vps_num_ptls_minus1, 0, total_num_olss - 1)` with `total_num_olss = 257` means the upper bound of the constraint is 256, but the `u(8)` format enforces the actual maximum to be 255. The constraint validation in CBS is advisory/checked after reading, and even if violated, the read value cannot exceed 255.

The report's claim that "256 can be encoded as 8-bit value 0x100" is incorrect — 0x100 requires 9 bits.

## Bitstream Design (for maximum coverage)

Despite the impossibility of triggering the claimed OOB, this PoC constructs the maximum-stress VPS:

| Field | Value | Rationale |
|-------|-------|-----------|
| vps_max_layers_minus1 | 1 | Enable multi-layer path |
| vps_all_independent_layers_flag | 0 | Enable OLS mode |
| vps_independent_layer_flag[1] | 1 | Layer 1 is independent |
| vps_ols_mode_idc | 2 | Enable num_output_layer_sets |
| vps_num_output_layer_sets_minus2 | 255 | total_num_olss = 257 |
| vps_num_ptls_minus1 | 255 | Maximum 8-bit value |
| vps_pt_present_flag[1..255] | 0 | Minimal PTL data |

## VVC NAL Unit Encoding

VVC NAL header (2 bytes):
- nal_unit_type = 14 (VVC_VPS_NUT)
- nuh_layer_id = 0
- nuh_temporal_id_plus1 = 1
- Encoding: (14 << 9) | (0 << 3) | 1 = 0x1C01 → bytes 0x1C, 0x01

## Conclusion

The reported vulnerability (OOB write at index 256) **cannot be triggered** because:
- The `u(8)` field encoding limits `vps_num_ptls_minus1` to [0, 255]
- `VVC_MAX_PTLS = 256` provides exactly enough space for all valid values
- There is no path to achieve index 256 via normal CBS VPS parsing

The PoC status is therefore **UNVERIFIED** — the crafted bitstream exercises the VPS parsing code at maximum coverage but does not trigger any crash.
