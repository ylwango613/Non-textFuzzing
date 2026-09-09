# VULN 001 Notes — Off-by-One OOB Heap Read in sbc_unpack_frame

## Vulnerability

**File:** `libavcodec/sbcdec.c`, lines 175–183  
**CWE:** CWE-125 (Out-of-bounds Read)

The loop that extracts one audio sample bit reads data before checking the guard:

```c
for (bit = 0; bit < bits[ch][sb]; bit++) {
    if (consumed > len * 8)   // BUG: should be >=
        return -1;
    if ((data[consumed >> 3] >> (7 - (consumed & 0x7))) & 0x01)
        audio_sample |= 1 << (bits[ch][sb] - bit - 1);
    consumed++;
}
```

When `consumed == len * 8` the guard `consumed > len * 8` is **false**, so
`data[consumed >> 3]` = `data[len]` is read one byte past the end of the buffer.
The guard fires correctly on the *next* iteration (`consumed = len*8 + 1 > len*8`),
returning `-1`.  The fix is `>=`.

---

## Trigger Conditions (Algebraic Analysis)

The OOB is reachable only when `sbc_unpack_frame` receives a buffer shorter
than what `ff_sbc_calculate_bits` requires.

### Why a complete frame cannot trigger the OOB

For any SBC mode M, N blocks, bitpool P, the parser computes frame length:

```
length = 4 + scale_factor_bytes + ceil((coeff * N * P + joint_bits) / 8)
```

`ff_sbc_calculate_bits` guarantees `sum(bits) ≤ P` across all subbands for each
channel (the allocation loop terminates when `bitcount == bitpool`).  Therefore:

```
total_audio_bits = N × sum(bits) ≤ N × P
payload_bits     = 8 × ceil(N × P / 8) ≥ N × P
→ total_audio_bits ≤ payload_bits   (always)
```

The decoder can never read past the end of a correctly-sized complete frame.
The vulnerability requires `len < expected_decoder_size`, i.e. a **truncated** frame.

### Concrete trigger (bitpool=8, MONO, 4sb, 4blk, SNR, SF=2)

Parser frame length = **10 bytes**.  A 9-byte frame (one byte short) would cause
the decoder to attempt to read bit 72 (`consumed=72 = 9×8 = len×8`) without the
correct guard stopping it.

---

## PoC Design

Frame parameters (chosen so that the SBC parser accepts 9 bytes as the expected
frame length, and the decoder needs to read beyond byte 8):

| Field       | Value           | Notes                                      |
|-------------|-----------------|---------------------------------------------|
| SYNC        | 0x9C            | SBC_SYNCWORD                               |
| FORMAT_BYTE | 0x02            | MONO, 4 blocks, SNR alloc, 4 subbands, 16 kHz |
| BITPOOL     | 8               | gives sum(bits)=8, 32 audio bits, 10-byte frame |
| CRC         | 0x13            | CRC-8/EBU of [0x02, 0x08, 0x22, 0x22]     |
| SF bytes    | 0x22 0x22       | scale_factor=2 for all 4 subbands          |
| Audio       | 3 bytes (trunc) | 9-byte truncated frame (parser expects 10) |

The crafted `.sbc` file consists of N complete 10-byte frames (to fill
`avformat_find_stream_info`'s probe buffer) followed by one 9-byte truncated
frame intended to be flushed at EOF.

---

## Why the PoC Cannot Be Verified via `ffmpeg -f sbc -i file.sbc -f null -`

Two independent blockers prevent demonstrating the crash:

### Blocker 1 — Parser EOF flush fails (AVERROR EINVAL)

The SBC parser (`sbc_parser.c`) buffers incomplete frames in `ff_combine_frame`'s
`ParseContext`.  When the demuxer hits EOF, `read_frame_internal` in
`libavformat/demux.c` line 1409 calls:

```c
parse_packet(s, pkt, st->index, /* flush= */ 1);
```

Inside `parse_packet`, `av_parser_parse2` is called with `buf_size=0`.
`av_parser_parse2` converts a NULL buffer to `dummy_buf[64]` (zeros) and calls
`sbc_parse(..., dummy_buf, 0)`.

In `sbc_parse`, the `if (pc->header_size)` branch computes:

```c
next = sbc_parse_header(pc->header, 3) - pc->buffered_size
     = 10 - 9 = 1
```

Then `ff_combine_frame(&pc->pc, next=1, &buf, &buf_size=0)` is called.
At line 227–228 of `parser.c`:

```c
if (next > *buf_size)      // 1 > 0  → TRUE
    return AVERROR(EINVAL);
```

The 9-byte buffered frame is **permanently discarded**.  The truncated packet
is never added to the decode queue, and the decoder never sees it.

### Blocker 2 — ASAN cannot detect a 1-byte OOB within packet padding

Even if the truncated frame reached the decoder, FFmpeg allocates **all** packets
with `AV_INPUT_BUFFER_PADDING_SIZE = 64` extra zeroed bytes (see
`libavutil/mem.c`, `av_packet_ref`).  A 9-byte SBC payload is stored in a
`9 + 64 = 73`-byte allocation.  `data[9]` through `data[72]` are valid (zeroed)
memory — AddressSanitizer has no way to distinguish them from in-bounds access.

Only a **custom allocator** that allocates exactly N bytes (or a direct harness
that calls `sbc_unpack_frame` with a stack buffer of size `len`) can produce the
detectable crash.

---

## ffmpeg Output Summary

The crafted file (with bitpool=5 complete 9-byte frames, a configuration chosen
to verify parser delivery) decodes successfully without errors:

```
20 frames decoded; 0 decode errors
```

No ASAN report was produced.

---

## Status

**UNVERIFIED** — The vulnerability is confirmed by static code analysis (the
`>` vs `>=` guard, the parser arithmetic proving it is only reachable for
truncated frames), but the `ffmpeg -f sbc -i` code path cannot deliver a
truncated frame to `sbc_unpack_frame`, and 64-byte packet padding renders the
single-byte OOB invisible to ASAN even under ideal conditions.

A direct harness calling `sbc_unpack_frame(buf, frame, 9)` with a 9-byte stack
buffer and ASAN (`-fsanitize=address`) would produce a detectable heap/stack OOB.
