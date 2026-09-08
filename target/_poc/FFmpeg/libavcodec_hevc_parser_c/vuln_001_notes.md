# VULN-001 Analysis Notes
## Integer overflow in pic_area_in_ctbs (ff_hevc_decode_nal_pps)

### Target
- Binary: `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg`
- Version: FFmpeg N-126435-gf93cd72dde (built 2026, ASAN+UBSAN)
- File: `libavcodec/hevc/ps.c`, function `setup_pps()`, ~line 2119

### Vulnerability Description (per report)
`pic_area_in_ctbs = sps->ctb_width * sps->ctb_height` is a signed `int`
multiplication. With large CTB dimensions the product overflows to a small
positive value, causing `av_malloc_array(pic_area_in_ctbs, 4)` to allocate
too little memory. Subsequent loops over `ctb_addr_rs = 0..ctb_width*ctb_height-1`
then write out-of-bounds into `ctb_addr_ts_to_rs[]`.

### Source Code - Vulnerable Lines
```c
// ps.c:2119-2123 (setup_pps)
int pic_area_in_ctbs = sps->ctb_width * sps->ctb_height;  // signed int!

pps->ctb_addr_rs_to_ts = av_malloc_array(pic_area_in_ctbs, sizeof(*pps->ctb_addr_rs_to_ts));
pps->ctb_addr_ts_to_rs = av_malloc_array(pic_area_in_ctbs, sizeof(*pps->ctb_addr_ts_to_rs));
pps->tile_id           = av_malloc_array(pic_area_in_ctbs, sizeof(*pps->tile_id));
```

### Constraint Analysis
#### av_image_check_size (libavutil/imgutils.c:301)
```c
if (w==0 || h==0 || w > INT32_MAX || h > INT32_MAX ||
    stride >= INT_MAX || stride*(h + 128ULL) >= INT_MAX)
    return AVERROR(EINVAL);
// stride = 8*w + 1024 (for AV_PIX_FMT_NONE)
```
This enforces: `(8w + 1024) * (h + 128) < 2,147,483,647`
Maximum area: ~268 million pixels. Maximum square side: ~16,000 pixels.

#### log2_ctb_size constraint (ps.c:1665)
```c
if (sps->log2_ctb_size < 4) {
    return AVERROR_INVALIDDATA;  // Minimum CTB size = 16x16
}
```

#### Required alignment (ps.c:1688)
```c
if (av_zero_extend(sps->width, sps->log2_min_cb_size) ||
    av_zero_extend(sps->height, sps->log2_min_cb_size))
    return AVERROR_INVALIDDATA;
// width and height must be divisible by 2^log2_min_cb_size (min=8)
```

### Overflow Feasibility
For `ctb_width * ctb_height` to overflow INT32:
- Need: `ctb_width * ctb_height > 2,147,483,647`
- Minimum CTB size = 16x16 (log2_ctb_size >= 4)
- Maximum: `ctb_width * ctb_height = (w/16) * (h/16)`
- From av_image_check_size: `w * h <= 268,000,000`
- Therefore: `ctb_width * ctb_height <= 268,000,000 / 256 = 1,046,875`

**Conclusion: 1,046,875 << 2,147,483,647 -- overflow is NOT possible in this build.**

The vulnerability as described requires either:
1. A different (older) `av_image_check_size` implementation without the stride check
2. A different code path bypassing the size check
3. A smaller minimum CTB size (< log2_ctb_size=4)

### PoC Strategy
Since the overflow is not triggerable, the PoC uses the closest-to-overflow
valid input to exercise the exact code path:
- Width = Height = 16000 (max passing av_image_check_size, divisible by 8)
- log2_min_cb_size = 3, log2_diff = 1 => log2_ctb_size = 4 (CTB 16x16)
- ctb_width = ctb_height = 1000, pic_area_in_ctbs = 1,000,000

### Expected ASAN Output
No crash expected. FFmpeg may print errors about missing slice data (only
VPS/SPS/PPS are provided, no slice NAL units), but the parameter set
parsing itself should succeed without memory errors.

### Files
- `vuln_001_gen.py`     -- crafted bitstream generator
- `vuln_001_input.265`  -- generated HEVC Annex B bitstream
- `vuln_001_run.sh`     -- runner script
- `vuln_001_result.txt` -- ffmpeg + ASAN output
- `vuln_001_status.txt` -- verdict (VERIFIED_CRASH / VERIFIED_BEHAVIOR / UNVERIFIED / ERROR)
