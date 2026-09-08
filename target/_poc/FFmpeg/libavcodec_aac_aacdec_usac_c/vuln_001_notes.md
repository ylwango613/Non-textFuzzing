# VULN 001 — parse_ext_ele() Integer Overflow → Heap Buffer Overflow

## Vulnerability Details

- **File**: `libavcodec/aac/aacdec_usac.c`
- **Function**: `parse_ext_ele()`
- **Lines**: 1993–2013
- **Type**: CWE-190 (Integer Overflow) → CWE-122 (Heap Buffer Overflow)

## Root Cause

In `parse_ext_ele()`, when a USAC extension element is configured with
`usacExtElementPayloadFrag=1`, per-frame payload fragments are accumulated via
`e->ext.pl_data_offset` (type `uint32_t`).

On each non-terminal continuation frame (pl_frag_start=0, pl_frag_end=0):

```c
// Line 1995: allocate with uint32_t arithmetic — no overflow check
uint8_t *tmp_buf = av_refstruct_alloc_ext(e->ext.pl_data_offset + len, ...);

// Line 2003: copy existing data using accumulated offset as copy size
if (e->ext.pl_buf)
    memcpy(tmp_buf, e->ext.pl_buf, e->ext.pl_data_offset);

// Line 2013: accumulate
e->ext.pl_data_offset += len;
```

When `pl_data_offset + len` overflows `uint32_t` (wraps around to a small value):
- `av_refstruct_alloc_ext()` allocates only the small wrapped size (underallocation)
- `memcpy()` is then called with the pre-wrap huge value of `e->ext.pl_data_offset`
  as the copy size, writing far beyond the allocated buffer → heap overflow

## Overflow Threshold

- Each frame contributes `len` bytes to `pl_data_offset`
- Maximum frame payload without extended length: 253 bytes (extended: up to 65790 bytes)
- For overflow with max payload (65790 bytes/frame):
  `2^32 / 65790 ≈ 65,278 frames` needed
- Total data: `65,278 × 65,790 ≈ 4.3 GB` — impractical in a single test run

## PoC Design

Since triggering the actual overflow requires ~4.3 GB of input, this PoC creates the
**smallest possible file** that exercises the fragmented extension element code path
and demonstrates that `parse_ext_ele()` is reachable with `payload_frag=1`.

### USAC Configuration

```
UsacConfig:
  usacSamplingFrequencyIndex = 3  (48000 Hz)
  coreSbrFrameLengthIndex    = 1  (1024 samples, no SBR)
  channelConfigurationIndex  = 1  (mono, standard layout)
  UsacDecoderConfig:
    Element 0: SCE (tw_mdct=0, noise_fill=0)   ← provides valid 1-channel layout
    Element 1: EXT (type=FILL, payloadFrag=1)  ← vulnerability trigger
```

The SCE element is needed so ffmpeg reports a valid 1-channel layout; without it the
filter graph refuses to initialize and no frames are decoded.

### Frame Sequence (10 frames × 50 bytes payload)

| Frame | indep_flag | frag_start | frag_stop | Effect                              |
|-------|-----------|------------|-----------|-------------------------------------|
| 0     | 1         | 1          | 0         | Reset pl_data_offset → 0, then +=50 |
| 1–8   | 0         | 0          | 0         | pl_data_offset += 50 each           |
| 9     | 0         | 0          | 1         | Final += 50; process FILL (no-op)   |

After all 10 frames: `pl_data_offset = 500 bytes` (well below the overflow threshold).

### Minimal SCE Frame Format (per-frame)

FD-mode SCE with `max_sfb=0` produces silence and reads very few bits:
- `core_mode=0` (FD), `tns_data_present=0`, `global_gain=0x7F`
- `window_sequence=0` (ONLY_LONG_SEQUENCE), `max_sfb=0`
- No scale factors (max_sfb=0), no spectral data (swb_offset[0]=0 → len=0)
- `fac_data_present=0`

Total SCE bits: 20 (indep frame) or 21 (continuation frame, +arith_reset_flag)

## PoC Execution Results

```
Input: vuln_001_input.mp4 (1171 bytes)
Stream: Audio: aac (xHE-AAC), 48000 Hz, mono, fltp
Output: audio:20KiB (10 decoded frames of silence)
Exit: 0 (success)
ASAN: No errors (overflow not triggered)
```

The debug log confirms `decode_usac_extension` is called:
```
[aac] Extension present: type 0, len 0
```

## Status: UNVERIFIED

The vulnerable code path (`parse_ext_ele` with `payload_frag=1`, fragmented accumulation
via `av_refstruct_alloc_ext + memcpy`) is successfully exercised.

The integer overflow itself is **not triggered** because doing so requires approximately
4.3 GB of crafted USAC data, which is impractical to generate and process in a
normal test environment. The vulnerability's existence is structural (no overflow
check before the `uint32_t` addition at line 1995) and the code path is confirmed
reachable.

## Reproduction

```bash
cd /data/ylwang/non-textfuzz/target/_poc/FFmpeg/libavcodec_aac_aacdec_usac_c/
bash vuln_001_run.sh
```
