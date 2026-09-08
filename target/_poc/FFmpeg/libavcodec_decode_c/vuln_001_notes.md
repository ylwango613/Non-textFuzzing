# VULN 001 — OOB Heap Write in discard_samples()

**File**: `libavcodec/decode.c`, function `discard_samples()`  
**CWE**: CWE-787 (Out-of-Bounds Write)  
**Severity**: High (heap OOB write, potentially exploitable)

---

## Vulnerability

`discard_samples()` in `libavcodec/decode.c` (around line 346) writes 10 bytes
into an `AVFrameSideData` buffer **without checking whether the buffer is large enough**:

```c
// Line 331: read side correctly guards with size >= 10
side = av_frame_get_side_data(frame, AV_FRAME_DATA_SKIP_SAMPLES);
if (side && side->size >= 10) {
    int skip_samples = AV_RL32(side->data);      // read OK
    ...
    discard_padding = AV_RL32(side->data + 4);   // read OK
    skip_reason = AV_RL8(side->data + 8);        // read OK
    discard_reason = AV_RL8(side->data + 9);     // read OK
}

// Line 346: write-back path has NO size check ← BUG
if ((avctx->flags2 & AV_CODEC_FLAG2_SKIP_MANUAL)) {
    if (!side && (avci->skip_samples || discard_padding))
        side = av_frame_new_side_data(frame, AV_FRAME_DATA_SKIP_SAMPLES, 10);
    if (side && (avci->skip_samples || discard_padding)) {
        AV_WL32(side->data,     avci->skip_samples);   // +0..+3
        AV_WL32(side->data + 4, discard_padding);      // +4..+7 ← OOB if size < 8
        AV_WL8(side->data + 8,  skip_reason);          // +8     ← OOB if size < 9
        AV_WL8(side->data + 9,  discard_reason);       // +9     ← OOB if size < 10
        avci->skip_samples = 0;
    }
    return 0;
}
```

**Preconditions for the OOB write:**

1. `AV_FRAME_DATA_SKIP_SAMPLES` side data exists on the frame with `size < 10`
2. `AV_CODEC_FLAG2_SKIP_MANUAL` is set (`-flags2 +skip_manual`)
3. `avci->skip_samples > 0` (set from `avctx->delay` = 1024 for AAC)

The first precondition is satisfied when a demuxer copies `AV_PKT_DATA_SKIP_SAMPLES`
with `size < 10` from the packet to the frame via `side_data_map()` in `decode.c:1492`.

---

## Attack Surface Analysis

### How SKIP_SAMPLES reaches the frame

`side_data_map()` in `decode.c` maps `AV_PKT_DATA_SKIP_SAMPLES` (packet level)
to `AV_FRAME_DATA_SKIP_SAMPLES` (frame level), preserving the `size` verbatim:

```c
// decode.c ~line 1520
sd_frame = av_frame_new_side_data(dst, type_frame, sd_pkt->size);  // size copied verbatim
memcpy(sd_frame->data, sd_pkt->data, sd_pkt->size);
```

Therefore, if a demuxer creates `AV_PKT_DATA_SKIP_SAMPLES` with `size < 10`,
the frame side data will also have `size < 10`, satisfying precondition (1).

### Can any demuxer produce size < 10?

**No.** Every demuxer in FFmpeg that creates `AV_PKT_DATA_SKIP_SAMPLES`
uses a hardcoded size of 10:

| Location | Code |
|----------|------|
| `libavformat/nutdec.c` `read_sm_data()` | `av_packet_new_side_data(pkt, AV_PKT_DATA_SKIP_SAMPLES, 10)` |
| `libavformat/demux.c` | `av_packet_new_side_data(pkt, AV_PKT_DATA_SKIP_SAMPLES, 10)` |
| `libavformat/matroskadec.c` | size=10 hardcoded |
| `libavformat/oggdec.c` | size=10 hardcoded |
| `libavformat/cafdec.c` | size=10 hardcoded |
| `libavformat/iamf_reader.c` | size=10 hardcoded |

### NUT SM_DATA analysis

The NUT container supports `SkipStart`/`SkipEnd` metadata via SM_DATA frames.
`read_sm_data()` in `nutdec.c` reads the integer values but always allocates
exactly 10 bytes for the side data, regardless of the values:

```c
// nutdec.c ~line 952
if (skip_start || skip_end) {
    uint8_t *dst = av_packet_new_side_data(pkt, AV_PKT_DATA_SKIP_SAMPLES, 10); // HARDCODED 10
    if (!dst) return AVERROR(ENOMEM);
    AV_WL32(dst,   skip_start);
    AV_WL32(dst+4, skip_end);
    // bytes 8-9 are zeroed by av_packet_new_side_data
}
```

Even crafting NUT SM_DATA with arbitrary `SkipStart` values (as done by this PoC)
produces `size=10`, not `size < 10`.

---

## PoC Approach

This PoC generates a minimal NUT/AAC file that exercises the
`discard_samples()` code path as closely as possible:

1. **`vuln_001_gen.py`**: Constructs a 187-byte NUT file containing:
   - MAIN_HEADER (frame code table supporting SM_DATA via FLAG_CODED frame)
   - STREAM_HEADER (AAC audio, 44100 Hz mono, codec_tag=0x000000FF)
   - SYNCPOINT (timestamp=0, back_ptr=syncpoint_pos)
   - One AAC frame with SM_DATA: `SkipStart=100`

2. **`vuln_001_run.sh`**: Runs:
   ```
   ffmpeg -flags2 +skip_manual -i vuln_001_input.nut -f null -
   ```
   The `-flags2 +skip_manual` flag enables the vulnerable write-back path.

### What actually happens at runtime

The SM_DATA in the NUT file causes `read_sm_data()` to create
`AV_PKT_DATA_SKIP_SAMPLES` with `size=10` and `skip_start=100`.
`side_data_map()` copies this to the frame: `size=10`.

In `discard_samples()` with SKIP_MANUAL set:
- `side->size >= 10` → TRUE → reads `skip_samples=100` from the side data
- `avci->skip_samples = 100` (overrides the AAC delay value of 1024)
- Write-back path: `side->size=10` → all 10 bytes are within bounds → **no OOB**

The vulnerability does NOT trigger because the side data has `size=10`, not `size < 9`.

---

## Root Cause Fix

Add the missing size check at the write-back path:

```c
// Proposed fix for decode.c ~line 346:
if (side && side->size >= 10 && (avci->skip_samples || discard_padding)) {
    AV_WL32(side->data,     avci->skip_samples);
    AV_WL32(side->data + 4, discard_padding);
    AV_WL8(side->data + 8,  skip_reason);
    AV_WL8(side->data + 9,  discard_reason);
    avci->skip_samples = 0;
}
```

---

## Status

**SKIPPED** — The vulnerability exists in the source code but cannot be
triggered via any standard file-based input. The trigger requires
`AV_FRAME_DATA_SKIP_SAMPLES` with `size < 10`, which no standard FFmpeg
demuxer can produce (all hardcode `size=10`).

To trigger the vulnerability programmatically (outside the scope of this PoC),
one would need to call `av_frame_new_side_data()` directly with `size < 10`
before passing the frame to a codec configured with `AV_CODEC_FLAG2_SKIP_MANUAL`.
