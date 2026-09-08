# VULN 001 — Heap OOB Read in mlp_parse() Parity Check Loop

## Vulnerability

- **File**: `libavcodec/mlp_parser.c`, lines 146–154
- **CWE**: CWE-125 Out-of-bounds Read

## Root Cause

The parity check loop in `mlp_parse()` uses `mp->num_substreams` (set from a
prior sync frame) to bound its iteration, but does not guard `p` against
exceeding `buf_size`:

```c
for (i = -1; i < mp->num_substreams; i++) {
    parity_bits ^= buf[p++];   // no bounds check on p
    parity_bits ^= buf[p++];
    if (i < 0 || buf[p-2] & 0x80) {
        parity_bits ^= buf[p++];
        parity_bits ^= buf[p++];
    }
}
```

`MAX_SUBSTREAMS` is 4, but `num_substreams` is a raw 4-bit field with a
maximum of 15, far beyond the legitimate range.

## PoC Approach

`vuln_001_gen.py` constructs a raw TrueHD (`.thd`) byte stream with two frames:

### Frame 1 — Valid sync frame (32 bytes)

- Bytes 0–1: length field → 32 bytes
- Bytes 4–7: `0xf8726fba` (TrueHD sync word)
- Bytes 8–31: major sync header with:
  - stream_type = `0xba` (TrueHD)
  - ratebits = 0 → 48 kHz
  - channel_arrangement = 1 (stereo)
  - `num_substreams = 15` (0xF, 4-bit field at bit offset 128 of the major sync)
  - Correct CRC-16 (polynomial 0x002D) checksum at bytes 30–31

After parsing this frame `mp->num_substreams` is set to **15**.

### Frame 2 — Minimal non-sync frame (8 bytes)

- Bytes 0–1: length field → 8 bytes
- Bytes 4–7: `0x00000000` (no sync word → `sync_present = 0`)
- All other bytes: zero

### OOB Access

With `num_substreams = 15` and `buf_size = 8`, the parity loop does:

| Iteration | Reads        | `p` after |
|-----------|-------------|-----------|
| i = −1    | buf[0..3]   | 4         |
| i = 0     | buf[4..5]   | 6         |
| i = 1     | buf[6..7]   | 8         |
| **i = 2** | **buf[8]**  | **OOB**   |

buf[8] through buf[63] (up to 56 bytes) are read out-of-bounds.

## Trigger Path

```
ffmpeg -i vuln_001_input.thd -f null -
  → av_parser_parse2()
    → mlp_parse()                    # frame 1: sync, sets num_substreams=15
    → mlp_parse()                    # frame 2: non-sync, OOB parity read
      → parity loop buf[8] OOB
```

## Expected ASAN Behavior

ASAN should report a **heap-buffer-overflow** (read) in `mlp_parse` at the
`buf[p++]` accesses inside the parity loop when the frame data resides in a
separately allocated buffer without sufficient trailing bytes.

At minimum, the parity check will fail on the garbage/OOB bytes, triggering
`lost_sync` and repeated re-sync attempts visible in ffmpeg output as
`mlpparse: Parity check failed.` log messages.
