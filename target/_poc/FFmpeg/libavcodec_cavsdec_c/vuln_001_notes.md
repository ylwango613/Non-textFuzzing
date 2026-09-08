# VULN 001: P-frame mb_type signed comparison bypass → OOB read

## Vulnerability

- **File**: `libavcodec/cavsdec.c` (~line 1126), `libavcodec/cavs.c` (line 495)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Function chain**: `decode_pic()` → `decode_mb_p()` → `ff_cavs_inter()` → `ff_cavs_partition_flags[mb_type]`

## Root Cause

In `decode_pic()` P-frame path:
```c
mb_type = get_ue_golomb(&h->gb) + P_SKIP + h->skip_mode_flag;
if (mb_type > P_8X8)      // signed comparison!
    ret = decode_mb_i(...);
else
    decode_mb_p(h, mb_type);
```

`get_ue_golomb()` returns `AVERROR_INVALIDDATA` (-22) when it sees ≥13 leading zero
bits (invalid Exp-Golomb code). With `P_SKIP=1` and `skip_mode_flag=0`:
```
mb_type = -22 + 1 + 0 = -21
```
The signed comparison `-21 > P_8X8(5)` is **FALSE**, so `decode_mb_p(h, -21)` is
called, which calls `ff_cavs_inter(h, -21)`, which reads
`ff_cavs_partition_flags[-21]` — an out-of-bounds memory read.

## PoC Approach

Construct a minimal CAVS bitstream:

1. **Sequence header** (`0x000001B0`): 16×16 frame, baseline profile.
   Provides width/height for decoder initialization.

2. **I-frame** (`0x000001B3`): Minimal valid intra picture.
   - 1 macroblock (16×16 → 1×1 MB grid).
   - `cbp_code=4` → `cbp_tab[4][0]=0` → no residual blocks to decode.
   - Must succeed for `DPB[0]` to receive a valid reference frame.
   - Without a successful I-frame decode, the P-frame would be rejected
     early by the `!h->DPB[0].f->data[0]` guard.

3. **P-frame** (`0x000001B6`): Crafted inter picture.
   - `picture_coding_type=01` (P-frame).
   - `skip_mode_flag=0` → no skip-count Golomb before `mb_type`.
   - MB payload filled with `0x00` bytes.
   - `get_ue_golomb()` sees 13+ leading zeros → returns `-22`.
   - `mb_type = -22 + 1 = -21` → signed comparison bypass → OOB.

Both the I-frame and P-frame are processed in the same `cavs_decode_frame()`
call (same packet). The `frame_start` guard allows up to 2 pictures
(`if (frame_start > 1)` check), and the DPB is updated after the I-frame
succeeds before the P-frame is attempted.

## Trigger

```
ffmpeg -i vuln_001_input.cavs -f null -
```

Expected: ASAN reports heap/stack OOB read in `ff_cavs_inter` or `ff_cavs_filter`
accessing `ff_cavs_partition_flags[-21]`.
