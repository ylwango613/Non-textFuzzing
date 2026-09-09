# VULN-001: OOB Read in rv40_strong_loop_filter via dmode Array Overrun

## Vulnerability Summary

- **File**: `libavcodec/rv40dsp.c`, function `rv40_strong_loop_filter()`, lines 519-535
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Arrays**: `rv40_dither_l[16]` and `rv40_dither_r[16]` (size 16, valid indices 0-15)
- **Access**: `rv40_dither_l[dmode + i]` where `i` ranges 0..3 in the filter loop

## Vulnerability Details

In `rv40_strong_loop_filter()`, the inner loop runs `for(i = 0; i < 4; i++)` and accesses:
```c
rv40_dither_l[dmode + i]  // lines 521, 533
rv40_dither_r[dmode + i]  // lines 525, 535
```

If `dmode = 15`, then:
- i=0: index 15 (valid, last element)
- i=1: index 16 (OUT OF BOUNDS)
- i=2: index 17 (OUT OF BOUNDS)
- i=3: index 18 (OUT OF BOUNDS)

## Trigger Path Analysis

The `dmode` parameter comes from `rv40_loop_filter()` in `rv40.c`:
```c
int dither = j ? ij : i*4;  // ij = i + j
```

The strong filter (`edge=1`) is called in two cases:
1. Top edge (line 488): when `!j` → `dither = i*4` (max 12 when i=3)
2. Left edge (line 495): when `!i` → `dither = j ? j : 0` (max 12 when j=12)

**Maximum dmode for the strong filter path = 12**, giving max array index = 12+3 = 15 (the last valid index).

The theoretical trigger condition (j=12, i=3, dmode=15) occurs in the ordinary filter path (`edge=0`), where `rv40_loop_filter_strength` returns 0 (early return when `!edge`), preventing the strong filter from being called.

## PoC Approach

1. Construct a minimal RealMedia (.rm) container using Python struct/bytes only
2. Embed an RV40 I-frame with 160x120 pixels (10×8 MB grid = 80 macroblocks)
3. Encode all MBs as 16x16 INTRA type (is16=1), which sets `IS_INTRA(mb_type)=true`
4. This causes `mb_strong=1` for all MBs in `rv40_loop_filter()`
5. The strong filter is invoked at MB boundaries with `edge=1`
6. ASAN-instrumented binary will detect any OOB reads

## RealMedia File Structure

```
.RMF (18 bytes) - file header
PROP (50 bytes) - stream properties  
MDPR (82 bytes) - media properties with RV40 codec data (codec_tag='RV40', 160x120)
DATA (18 bytes header + 1 packet) - video packet
  Packet: 12-byte header + hdr(0x41) + seq(0x00) + RV40 slice data
    RV40 slice: valid slice header for 160x120 I-frame + 8192 bytes of MB data
```

## RV40 Slice Header (5 bytes, 39 bits)

```
Byte 0: 0x14 = 0 00 10100  (valid=0, type=I, quant=20)
Byte 1: 0x00 = 00 00 0 000  (reserved=0, vlc_set=0, skip=0, pts[0-2]=0)
Byte 2: 0x00 = 00000000    (pts[3-10]=0)
Byte 3: 0x00 = 00 000 000  (pts[11-12]=0, width_t=0→160, height_t=0→120)
Byte 4: 0x01 = 0000000 1   (start_offset=0 [7 bits], is16=1 for MB0)
```

## Expected Result

Based on code analysis:
- The maximum `dmode` reachable in the strong filter path is **12** (not 15)
- Maximum array index accessed: 12+3=15, which is the **last valid index** (array size 16)
- Therefore, no actual OOB occurs in this code version

The PoC will either:
- **UNVERIFIED**: Frame decodes partially/fully, loop filter runs without OOB errors
- **VERIFIED_BEHAVIOR**: Decoder crashes due to garbage bitstream data
- **VERIFIED_CRASH**: ASAN detects OOB if global array red zones are enabled

## Expected ASAN Output (if triggered)

```
==XXXXX==ERROR: AddressSanitizer: global-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in rv40_strong_loop_filter libavcodec/rv40dsp.c:521
    #1 0x... in rv40_h_strong_loop_filter libavcodec/rv40dsp.c:560
    #2 0x... in rv40_adaptive_loop_filter libavcodec/rv40.c:321
    #3 0x... in rv40_loop_filter libavcodec/rv40.c:489
```
