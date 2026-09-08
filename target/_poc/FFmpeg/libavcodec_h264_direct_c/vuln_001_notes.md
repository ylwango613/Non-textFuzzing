# VULN 001: OOB Read via Negative mb_xy in H.264 Field-Picture B-Slice Direct Motion

## Vulnerability
- **File**: libavcodec/h264_direct.c
- **Functions**: pred_spatial_direct_motion() / pred_temp_direct_motion()
- **Lines**: 302-305 / 354-357 (spatial); 521-524 / 579-582 (temporal)
- **CWE**: CWE-125 Out-of-bounds Read

## Trigger Mechanism

### Code Path
```
ffmpeg -i crafted.h264 -f null -
  -> avformat_open_input()
  -> avcodec_send_packet()
  -> ff_h264_execute_decode_slices()
  -> decode_slice()
  -> ff_h264_decode_mb_cavlc()      [IS_DIRECT(mb_type) branch, line 936-937]
  -> ff_h264_pred_direct_motion()
  -> pred_temp_direct_motion()      [for direct_spatial_mv_pred=0]
```

### Key Conditions Required
1. SPS: frame_mbs_only_flag=0, mb_adaptive_frame_field_flag=0 (PAFF)
2. IDR TOP FIELD: field_pic_flag=1, bottom_field_flag=0 → stored as reference with field_picture=1
3. BOTTOM FIELD B-slice: field_pic_flag=1, bottom_field_flag=1
4. B-slice first MB = B_Direct_16x16 (IS_DIRECT set)
5. In ff_h264_direct_ref_list_init():
   - h->picture_structure = PICT_BOTTOM_FIELD = 2
   - L1[0].reference = PICT_TOP_FIELD = 1
   - !(2 & 1) = true AND !parent->mbaff = true
   - → col_fieldoff = 2*1 - 3 = -1

### Claimed OOB
The vulnerability report claims that with col_fieldoff=-1 and first MB at mb_y=0:
- mb_y += col_fieldoff → mb_y = -1
- mb_xy += mb_stride * col_fieldoff → mb_xy negative
- Negative mb_xy used to index parent->mb_type[], h->mb2b_xy[], parent->ref_index[]

### Analysis Finding: UNVERIFIED

**Critical observation**: FFmpeg initializes the first MB of any BOTTOM FIELD slice at mb_y=1, NOT mb_y=0.

In h264_slice.c `h264_field_start()` at lines 1954-1957:
```c
sl->resync_mb_y = sl->mb_y = (sl->first_mb_addr / h->mb_width) <<
                             FIELD_OR_MBAFF_PICTURE(h);
if (h->picture_structure == PICT_BOTTOM_FIELD)
    sl->resync_mb_y = sl->mb_y = sl->mb_y + 1;  // +1 for BOTTOM FIELD
```

For a BOTTOM FIELD with first_mb_in_slice=0:
- Initial: mb_y = 0 << 1 = 0
- BOTTOM FIELD correction: mb_y = 0 + 1 = **1**

Therefore, in pred_temp_direct_motion():
- mb_y = sl->mb_y = **1** (not 0)
- mb_xy = sl->mb_xy = 0 + 1 * mb_stride = **mb_stride** (e.g., 2 for 1-wide frame)
- After col_fieldoff=-1: mb_y = 1 + (-1) = **0** (valid)
- After adjustment: mb_xy = mb_stride + mb_stride*(-1) = **0** (valid)

The accesses parent->mb_type[0], h->mb2b_xy[0], parent->ref_index[0][0] are all valid indices.

**Fundamental constraint**: For any PAFF BOTTOM FIELD picture, the minimum initial mb_y for any MB is 1 (mb_stride). After col_fieldoff=-1 adjustment, the minimum mb_xy is 0. A NEGATIVE mb_xy via col_fieldoff=-1 is **mathematically impossible** in this code path.

## PoC Approach

The PoC (`vuln_001_gen.py`) generates:
1. SPS with PAFF enabled (frame_mbs_only_flag=0, mb_adaptive_frame_field_flag=0)
2. PPS with CAVLC encoding
3. IDR TOP FIELD with I_PCM macroblock (simplest intra coding)
4. BOTTOM FIELD B-slice with B_Direct_16x16 as first macroblock (temporal direct mode)

The bitstream successfully reaches the vulnerable code path:
- pred_temp_direct_motion() IS called
- col_fieldoff IS set to -1
- The col_fieldoff adjustment IS applied (mb_y: 1→0, mb_xy: 2→0)
- But accesses at mb_xy=0 are within-bounds

## Status

**UNVERIFIED**: The vulnerability's code path is confirmed reachable and the col_fieldoff=-1 adjustment does occur. However, due to FFmpeg's BOTTOM FIELD mb_y+1 initialization, the resulting mb_xy is 0 (valid) rather than negative. No actual OOB read is triggered with a standard PAFF bitstream.

The vulnerability description may be:
- Based on static analysis not accounting for the dynamic BOTTOM FIELD +1 correction
- Applicable to an older FFmpeg version
- Triggerable through a non-standard decoder state path not reproduced here
