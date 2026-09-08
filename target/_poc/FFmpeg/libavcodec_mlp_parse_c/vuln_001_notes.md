# VULN 001 — mlp_parser Heap OOB Read (num_substreams unvalidated)

## Vulnerability Summary

**CWE-125** Out-of-bounds Read in `mlp_parse()` / `ff_mlp_read_major_sync()`.

- **Source** (`mlp_parse.c:160`): `mh->num_substreams = get_bits(gb, 4)` — a 4-bit value (max 15) read directly from the bitstream with no upper-bound check; stored into `mp->num_substreams`.
- **Sink** (`mlp_parser.c:146-154`): the parity loop runs `(1 + mp->num_substreams)` iterations, each reading at least 2 bytes of `buf[]`, without checking `p < buf_size`.

## Parity-loop Code (mlp_parser.c:145-154)

```c
parity_bits = 0;
for (i = -1; i < mp->num_substreams; i++) {   // 1+15 = 16 iterations
    parity_bits ^= buf[p++];                   // read buf[p], no bounds check
    parity_bits ^= buf[p++];
    if (i < 0 || buf[p-2] & 0x80) {
        parity_bits ^= buf[p++];
        parity_bits ^= buf[p++];
    }
}
```

With `num_substreams = 15`:
- Iteration `i = -1` (always): reads 4 bytes (p advances to 4)
- Iterations `i = 0..14`: reads 2–4 bytes each

Minimum bytes needed: 4 + 15×2 = **34 bytes**. A 4-byte frame causes OOB reads starting at `buf[4]`.

## Two-Frame PoC Strategy

**Frame 1 (sync frame, 32 bytes):**  
Contains the TrueHD major sync header (`0xF8726FBA`) at byte offset 4.  
The `num_substreams` field (4 bits at bit position 128 of the sync header) is set to `0xF = 15`. A valid CRC-16 (polynomial `0x002D`) checksum is computed and stored so that `ff_mlp_read_major_sync()` accepts the frame and sets `mp->num_substreams = 15`.

**Frame 2 (non-sync frame, 4 bytes):**  
Follows immediately. Contains only 4 bytes. The parser sees `buf_size < 8`, so `sync_present = false`, and enters the parity-check loop. The loop reads `buf[4]` and beyond — past the end of the 4-byte allocation — triggering a heap out-of-bounds read.

## File Format Details

| Field | Value | Notes |
|---|---|---|
| Frame 1 length field | `0x0010` (AV_RB16) | (0x010 & 0xFFF) × 2 = 32 bytes |
| Sync word | `0xF8726FBA` at frame[4:8] | TrueHD type (0xBA) |
| `ratebits` | 0 | 48 000 Hz sample rate |
| `channel_arrangement_stream1` | 1 | L+R stereo |
| `channel_arrangement_stream2` | 1 | L+R stereo |
| **`num_substreams`** | **15** | triggers OOB |
| Checksum | computed by gen.py | CRC-16/0x002D over sync_hdr[0:24] XOR LE16(sync_hdr[24:26]) |
| Frame 2 length field | `0x0002` | (0x002 & 0xFFF) × 2 = 4 bytes |

## Trigger Command

```
ffmpeg -f truehd -i vuln_001_input.thd -f null -
```

`-f truehd` forces the TrueHD demuxer (bypasses probe score requirement).
