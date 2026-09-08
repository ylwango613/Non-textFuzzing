# VULN 001 — Off-by-8 Bounds Check in cmv_decode_frame — SKIPPED

## Status: SKIPPED

## Reason: Cannot Be Triggered via FFmpeg Command Line

The vulnerability cannot be demonstrated by passing a crafted media file to the
ffmpeg binary, because the 1-byte OOB read always falls within FFmpeg's
guaranteed zero-filled allocation padding, which ASAN does not flag.

---

## Vulnerability Description

**File**: `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/eacmv.c`  
**Function**: `cmv_decode_frame()`  
**Lines**: 189–198  
**Type**: CWE-125 Out-of-bounds Read (1-byte)

### Buggy Code Path

```c
// Line 185
unsigned size = AV_RL32(buf + 4);

// Line 189 — off-by-one: uses '>' instead of '>='
if (size > buf_end - buf - EA_PREAMBLE_SIZE)
    return AVERROR_INVALIDDATA;

// Line 191 — advance buf by size
buf += size;
// If size == (buf_end - buf_initial - EA_PREAMBLE_SIZE), buf is now at buf_end - 8

// Line 197 — skip the next chunk preamble
buf += EA_PREAMBLE_SIZE;
// buf is now exactly at buf_end

// Line 198 — 1-byte OOB read
if (!(buf[0] & 1) && buf_end - buf < s->width * s->height * ...)
    return AVERROR_INVALIDDATA;
```

The bounds check at line 189 uses strict `>` rather than `>=`. This allows
`size` to equal `buf_end - buf_initial - EA_PREAMBLE_SIZE`, which is the
maximum value that passes the check. After advancing `buf` by `size` and then
by another `EA_PREAMBLE_SIZE` (8 bytes), `buf` equals `buf_end` exactly. The
subsequent dereference `buf[0]` at line 198 reads one byte past the end of the
logical packet data — a 1-byte OOB read.

---

## Why It Cannot Be Triggered via `ffmpeg -i <crafted.cmv>`

### FFmpeg's Allocation Guarantee

The FFmpeg packet allocation path (e.g., `av_new_packet()`, `av_packet_from_data()`,
and all demuxers that call these) always appends `AV_INPUT_BUFFER_PADDING_SIZE`
(currently 64 bytes) of **zero-filled padding** immediately after `avpkt->data`.
This padding is part of the same `malloc()` block as the packet data.

See `libavcodec/avpacket.c`:
```c
// av_new_packet allocates size + AV_INPUT_BUFFER_PADDING_SIZE bytes total
// and zero-fills the trailing padding
```

### Effect on the OOB Read

When `buf` equals `buf_end` and `buf[0]` is read:
- The address `buf_end` points to the first byte of the zero-filled padding
- This is **valid, allocated memory** from the OS/allocator perspective
- ASAN tracks overflows at the allocator granularity; reads within the same
  allocation do not trigger a heap-buffer-overflow report
- The byte read is `0x00`

### Functional Effect Only

With `buf[0] == 0`:
- `!(buf[0] & 1)` evaluates to `!0 == 1` (true)
- The condition on line 198 evaluates the size check on the right side
- Because `buf_end - buf == 0` (no frame data remains), the size check likely
  fails and returns `AVERROR_INVALIDDATA`

The only observable effect is an `AVERROR_INVALIDDATA` error return, which
ffmpeg logs as a decode error. No crash, no memory corruption, no ASAN alert.

---

## Why This Is Not Demonstrable

| Requirement | Status |
|---|---|
| Logical OOB read exists in source | Yes — confirmed by code inspection |
| OOB read reaches truly unallocated memory | No — hits zero-fill padding |
| ASAN would flag with real ffmpeg binary | No — within same malloc block |
| Crafted file can bypass padding mitigation | No — padding is always present |
| Alternative trigger (unit test / custom harness) | Possible, but not via `ffmpeg -i` |

A dedicated fuzz harness that bypasses FFmpeg's packet allocation API and
provides a buffer without padding could demonstrate the read to ASAN. However,
such a harness does not constitute a PoC via the ffmpeg command line, which is
the scope of this task.

---

## Conclusion

The vulnerability is real at the source level (incorrect bounds check allows a
1-byte read past the logical end of packet data), but is **effectively mitigated**
by FFmpeg's mandatory `AV_INPUT_BUFFER_PADDING_SIZE` zero-fill padding in all
normal API usage paths. It cannot produce a crash, ASAN report, or other
detectable anomalous behavior when triggered through `ffmpeg -i <crafted.cmv>`.

**Status: SKIPPED**
