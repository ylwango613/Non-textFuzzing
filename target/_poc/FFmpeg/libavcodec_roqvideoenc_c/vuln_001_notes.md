# VULN-001: Heap Buffer Overflow in FFmpeg roqvideoenc.c

## Summary

A heap buffer overflow exists in `roq_encode_frame()` in
`libavcodec/roqvideoenc.c`. The output packet buffer is allocated using a size
formula that underestimates the bytes actually written, leading to writes past
the end of the allocated buffer when the encoding approaches its theoretical
maximum density.

## Vulnerable Code

**File:** `libavcodec/roqvideoenc.c`
**Function:** `roq_encode_frame()`, line ~1070

```c
size = ((roq->width * roq->height / 64) * 138 + 7) / 8 + 256 * (6 + 4) + 8;
```

This formula accounts for:
- Per-8x8 block encoding bits: `((w*h/64)*138+7)/8`
- Codebook data: `256*(6+4)` bytes (256 CB2 x 6 bytes + 256 CB4 x 4 bytes)
- Frame VQ chunk header: `+8` bytes

It does **not** account for:
1. **8-byte `RoQ_QUAD_CODEBOOK` chunk header** written unconditionally by
   `write_codebooks()` when `numCB2 > 0` (lines ~614-617).
2. **16-byte `RoQ_INFO` info chunk** written on the first frame only by
   `roq_write_video_info_chunk()` (~line 1087), which writes 2+4+2+2+2+4 = 16 bytes.

There is also a secondary +8-bit rounding artefact from a FIXME in the
frame-data accumulator when the number of CCC-coded 8x8 blocks is odd — this
does not on its own cause overflow but compounds with the above.

## Overflow Sizes

| Scenario | Extra bytes written beyond allocation |
|---|---|
| Non-first frame with numCB2 > 0, all-CCC encoding | 8 bytes (QUAD_CODEBOOK header) |
| First frame with numCB2 > 0, all-CCC encoding | 24 bytes (8 + 16) |

For the overflow to fire the actual frame data must reach within 24 bytes of the
formula-capped maximum `((w*h/64)*138+7)/8`.

## Rate-Distortion Analysis

The RoQ encoder chooses between four coding modes per 8x8 block:

```
MOT  ( 2 bits) — motion-compensated skip
FCC  (10 bits) — single CB4 enlarged reference
SLD  (10 bits) — CB4 vector, CB4 index
CCC  (34 bits/sub-cell x 4 = 138 bits) — four independent CB2 pairs
```

With encoder lambda=0 (set via `-q:v 0.009` which yields `global_quality=1`
and thus `frame->quality=1` and `enc->lambda = 1-1 = 0`) the encoder selects
purely on distortion.  Since four independent CB2 lookups can always match a
block at least as well as one enlarged CB4 entry, `dist_CCC <= dist_SLD`
always, so CCC mode always wins or ties.

For the overflow, every block AND every 4x4 sub-cell within each block must
choose CCC (138 bits each) to reach the per-frame maximum.

## PoC Strategy

1. `vuln_001_gen.py` — builds a minimal valid AVI with two 512x512 BGR24 frames
   of cryptographic-quality random pixels (`os.urandom`).  512x512 means 64
   blocks per CB4 cluster; the resulting centroid is the average of 64 distinct
   random blocks — a blurry grey value far from any individual block's optimal
   CB2 pair assignment, maximising the fraction of blocks that choose CCC.

2. `vuln_001_run.sh` — encodes via the ASAN-instrumented ffmpeg binary with:
   - `-c:v roqvideo` — select the vulnerable encoder
   - `-q:v 0.009` — sets `global_quality=1` so `lambda=0` in the encoder
   - `-quake3_compat 0` — disables the per-frame 65535-byte size cap that would
     otherwise force lambda upward and reduce CCC density

## Test Results

Best run (512x512, 2 frames, random noise, lambda=0, quake3_compat=0):

| Metric | Value |
|---|---|
| Output file size | 144 440 bytes |
| Avg frame data per frame | ~69 632 bytes |
| Theoretical all-CCC max | 70 656 bytes |
| CCC encoding density | ~98.55% |
| Overflow threshold (1st frame) | 70 632 bytes |
| Shortfall | ~1 000 bytes |
| ASAN output | none |
| Exit code | 0 |

## Why the Overflow Was Not Triggered

The ELBG vector quantiser (`avpriv_elbg_do` with 1 iteration) initialises
centroids by sampling actual blocks from the image.  Sampled blocks sit exactly
at their own centroid, giving `dist_SLD = 0` for those blocks.  Even with
`dist_CCC = 0` (perfect CB2 match), the encoder's tie-break selects SLD, so
a small fraction (~1-2%) of sub-cells always use SLD regardless of input entropy
or resolution.  This fraction is structurally bounded away from zero by the VQ
initialisation, keeping encoded density ~1000 bytes below the overflow threshold
across all tested inputs.

## Expected ASAN Output (if triggered)

```
==NNNNN==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 1 at 0x... thread T0
    #0 ... in bytestream_put_byte ...
    #1 ... in write_codebooks ...  (or roq_write_video_info_chunk)
    #2 ... in roq_encode_frame ...
```

## Impact

- **CWE-122:** Heap Buffer Overflow
- **Exploitability:** Low in practice; requires a VQ codebook initialisation
  that places no centroid at any block in the input, which the ELBG never does
  with standard video content.
- **Security relevance:** The allocation formula is provably wrong by 24 bytes on
  the first frame; a future optimisation to the VQ initialiser or a crafted
  initialisation seed could make the overflow reliably triggerable.
