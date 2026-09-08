# PoC Notes: Off-by-4 OOB Read in HQ/HQA Slice Offset Bounds Check

## Vulnerability Summary

- **File**: `libavcodec/hq_hqa.c`
- **Functions**: `hq_decode_frame()` (lines 176–184), `hqa_decode_frame()` (lines 302–311)
- **CWE**: CWE-125 Out-of-bounds Read
- **Type**: Off-by-4 in bounds check

## Root Cause

In `hq_hqa_decode_frame()`:
```c
data_size = bytestream2_get_bytes_left(gbc);  // captures size BEFORE consuming tag
tag       = bytestream2_get_le32u(gbc);        // consumes 4 bytes of tag
hq_decode_frame(ctx, pic, gbc, tag >> 24, data_size);  // passes original data_size
```

In `hq_decode_frame()`:
```c
const uint8_t *src = gbc->buffer;  // src now points 4 bytes PAST the start of data_size
// ...
if (slice_off[slice + 1] > data_size)   // BUG: should be > (data_size - 4)
// ...
init_get_bits(&gb, src + slice_off[slice],
              (slice_off[slice + 1] - slice_off[slice]) * 8);
```

Because `src` is 4 bytes into the region measured by `data_size`, the maximum valid
end offset for slice data from `src`'s perspective is `data_size - 4`. The current
check allows up to `data_size`, allowing `src + data_size` = 4 bytes past the end
of the allocated packet.

## PoC Approach

An AVI file is constructed with:
- FOURCC `CUVC` (Canopus HQ/HQA, per `libavformat/riff.c` line 447)
- One video frame containing a crafted HQ bitstream

The HQ frame (100 bytes) has:
- Tag: `55 56 43 00` → LE32 = `0x00435655`, matches HQ path, profile 0 (160×120, 8 slices)
- 9 slice offsets (24-bit BE, measured from tag byte 0):
  - `stored[0] = 31` → `slice_off[0] = 27` (minimum valid value)
  - `stored[1] = 104` → `slice_off[1] = 100 = data_size` ← **OOB trigger**
  - `stored[2..8] = 104` → `slice_off[2..8] = 100` (equal to [1] → secondary break)

## Trigger Path

```
ffmpeg -i crafted.avi -f null -
  → avi demuxer reads "00dc" chunk (100 bytes) as packet
  → hq_hqa_decode_frame()
      data_size = 100
      tag = 0x00435655  →  HQ path
      hq_decode_frame(gbc, prof=0, data_size=100)
          src = avpkt->data + 4
          slice_off[0] = 27, slice_off[1] = 100
          Check for slice 0: 100 > 100 → FALSE (PASSES — BUG)
          init_get_bits(&gb, src+27, 73*8)
              buffer start = avpkt->data + 31  (valid)
              buffer end   = avpkt->data + 104  (4 bytes PAST avpkt->size=100)
          hq_decode_mb × 10 run on OOB-extended buffer
          Slice 0 decoded (partially, with zero-data VLC result)
          Slice 1 check: slice_off[1] >= slice_off[2] → 100 >= 100 → TRUE → break
          "Invalid slice size 100" printed  ←  this is for slice 1, NOT slice 0
          return 0
```

## Observed Behavior

- The "Invalid slice size 100" message IS printed — but for **slice 1** (equal offsets)
- **Slice 0 is NOT rejected** despite `slice_off[1] = data_size`; the flawed check passes
- `init_get_bits` is called with a buffer whose `buffer_end` is 4 bytes past the packet
- FFmpeg reports `frame=1` — the frame is partially decoded and returned
- No ASAN hard crash: FFmpeg's `av_new_packet()` appends 64 bytes of padding after
  `avpkt->size`, so the 4-byte OOB lands in that padding region; ASAN does not flag it

## Why This Is Still a Real Vulnerability

1. **Logical OOB is confirmed**: the bounds check should have rejected slice 0 (`100 > 96`)
   but instead allowed it, enabling `init_get_bits` to set up an out-of-bounds buffer
2. **Without padding**: in codepaths where packets are not padded (direct memory slices,
   custom allocators, or when `AV_INPUT_BUFFER_PADDING_SIZE` is reduced), this becomes a
   hard heap OOB read
3. **Information disclosure**: in heap-groomed scenarios the 4 bytes beyond the packet
   could contain heap metadata or adjacent object data
4. **Identical pattern in `hqa_decode_frame`** at lines 302–311 is also vulnerable

## Expected vs. Actual

| Condition | Expected (correct) | Actual (buggy) |
|---|---|---|
| `slice_off[1] > data_size - 4` = `100 > 96` | TRUE → reject slice | check not used |
| `slice_off[1] > data_size` = `100 > 100` | FALSE → (should reject anyway) | FALSE → accept slice |
| Slice 0 processed | No | Yes |
| `init_get_bits` OOB buffer | Should not happen | Happens |

## Fix

Change the bounds check from:
```c
slice_off[slice + 1] > data_size
```
to:
```c
data_size < 4 || slice_off[slice + 1] > data_size - 4
```
(and equivalently in `hqa_decode_frame`)
