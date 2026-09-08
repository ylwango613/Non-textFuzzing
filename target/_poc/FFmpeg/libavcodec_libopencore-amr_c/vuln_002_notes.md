# VULN 002: AMR-WB Decoder buf[0] OOB Read Before Size Check

## Vulnerability Summary

- **ID**: VULN 002
- **File**: `libavcodec/libopencore-amr.c`
- **Function**: `amr_wb_decode_frame()`
- **Lines**: 339-358
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-476 (NULL Pointer Dereference)

## Vulnerable Code

```c
static int amr_wb_decode_frame(AVCodecContext *avctx, AVFrame *frame,
                               int *got_frame_ptr, AVPacket *avpkt)
{
    const uint8_t *buf = avpkt->data;       // line 339
    int buf_size       = avpkt->size;       // line 340
    ...
    static const uint8_t block_size[16] = {18, 24, 33, 37, 41, 47, 51, 59, 61, 6, 6, 0, 0, 0, 1, 1};

    /* get output buffer */
    frame->nb_samples = 320;
    if ((ret = ff_get_buffer(avctx, frame, 0)) < 0)
        return ret;

    mode        = (buf[0] >> 3) & 0x000F;   // LINE 351: BUG - reads buf[0] BEFORE checking buf_size
    packet_size = block_size[mode];

    if (packet_size > buf_size) {           // line 354: size check comes AFTER the read
        av_log(...);
        return AVERROR_INVALIDDATA;
    }
```

The bug is that `buf[0]` is dereferenced at line 351 before `buf_size` is validated.
If `avpkt->size == 0`, then `avpkt->data` may be NULL, causing a NULL pointer dereference (CWE-476).
If `avpkt->size > 0` but the buffer is too small, it may cause an OOB read (CWE-125).

## AMR-WB File Format

- Magic header: `#!AMR-WB\n` (9 bytes: 0x23 0x21 0x41 0x4D 0x52 0x2D 0x57 0x42 0x0A)
- Frame header byte: bits [6:3] = FT (Frame Type), determines payload length
- FT determines how many bytes of payload follow (via block_size table)

### Decoder block_size table (16 entries):
| FT  | 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|-----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| sz  | 18 | 24 | 33 | 37 | 41 | 47 | 51 | 59 | 61 | 6 | 6  | 0  | 0  | 0  | 1  | 1  |

### Parser amrwb_packed_size table (used by AMR parser):
| FT  | 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|-----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| sz  | 18 | 24 | 33 | 37 | 41 | 47 | 51 | 59 | 61 | 6 | 1  | 1  | 1  | 1  | 1  | 1  |

## Trigger Conditions

The vulnerability requires `avpkt->data == NULL` (when `avpkt->size == 0`) to reach
the `amr_wb_decode_frame()` function. This can happen when:

1. **Flush path**: At EOF, FFmpeg sends a flush/drain signal by calling the decoder
   with a NULL packet (`avpkt->data == NULL, avpkt->size == 0`).
2. **Parser output**: If the AMR parser somehow produces a 0-size output packet.

### Frame Types of Interest

- **FT=11,12,13**: decoder `block_size=0`, parser `packed_size=1`
  - Parser creates a 1-byte packet, decoder receives it
  - Bug: `buf[0]` read succeeds (valid), then `packet_size=0`, then `!packet_size` true
  - Result: "amr packet_size invalid" error (graceful, no crash with size=1)
- **FT=15**: decoder `block_size=1`, parser `packed_size=1`
  - Valid 1-byte frame, decoder succeeds
- **FT=0 with truncated payload**: parser waits for more data (END_NOT_FOUND path)

## Build Environment Finding

**CRITICAL**: The `libopencore_amrwb` decoder is **NOT compiled** into the test binary.

```
# build_test/config.h:
#define CONFIG_LIBOPENCORE_AMRWB 0
```

The build configuration does NOT include `--enable-libopencore-amrwb`, so:
- The vulnerable `amr_wb_decode_frame()` in `libopencore-amr.c` is NOT compiled
- The binary uses the native `amrwb` decoder from `amrwbdec.c` instead
- `ffmpeg -decoders` shows only `amrwb` and `amrnb`, not `libopencore_amrwb`
- Attempting `-codec:a libopencore_amrwb` gives: "Unknown decoder 'libopencore_amrwb'"

## Test Results

All 8 test cases were run against the ASAN build. None triggered an ASAN error:

| Test | File | Result |
|------|------|--------|
| 1 | magic-only AWB | Exit 0, no frames, no crash |
| 2 | FT=15 single frame | Exit 0, 1 frame decoded (native decoder) |
| 3 | FT=11 frame | Exit 69, "Invalid mode 11" (native decoder rejects) |
| 4 | FT=0 truncated | Exit 69, "Frame too small" (native decoder rejects) |
| 5 | magic-only + -f amrwb | Exit 0, 1 "corrupted frame" decoded |
| 6 | raw FT=11 + -f amrwb | Exit 69, "Invalid mode 11" (native decoder) |
| 7 | empty file + -f amrwb | Exit 0, 0 packets, no crash |
| 8 | FT=9 partial frame | Exit 69, "Frame too small" |

The native `amrwb` decoder (`amrwbdec.c`) has its own different validation logic
and does not exhibit the same code-level bug at the same location.

## Attack Scenario (if libopencore was compiled in)

To trigger the bug with a libopencore-enabled build:
1. Craft a file: `#!AMR-WB\n` magic header with no valid frames, or a file that
   forces the flush path to be taken.
2. The flush/drain call would pass `avpkt->data=NULL, avpkt->size=0` to `amr_wb_decode_frame`.
3. Line 351 dereferences NULL: `mode = (buf[0] >> 3) & 0x000F` → SIGSEGV/ASAN crash.

Alternatively, use `vuln_002_ft11.awb` (FT=11, 1-byte packet) to trigger the
`block_size[11]=0` path, hitting the "amr packet_size invalid" error which is a
secondary symptom of the missing pre-check. With a size=0 packet, the crash happens
before that check.

## Fix (Suggested)

Add a buf_size check before dereferencing buf[0]:

```c
    // ADD before line 351:
    if (buf_size == 0 || !buf) {
        av_log(avctx, AV_LOG_ERROR, "AMR-WB frame is empty\n");
        return AVERROR_INVALIDDATA;
    }
    mode = (buf[0] >> 3) & 0x000F;   // line 351, now safe
```
