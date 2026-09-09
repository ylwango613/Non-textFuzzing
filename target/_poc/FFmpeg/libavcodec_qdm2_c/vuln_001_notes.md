# VULN-001 Notes: CWE-125 OOB Heap Read in qdm2_decode_super_block()

## Vulnerability Location
- **File**: `libavcodec/qdm2.c`
- **Lines**: 1181–1243 (`qdm2_decode_super_block`)
- **Specific site**: line 1192 `init_get_bits8(&gb, header.data, header.size)`

## Root Cause
`qdm2_decode_sub_packet_header()` reads `header.size` as an attacker-controlled
16-bit big-endian value (up to 65535). The subsequent call:

```c
ret = init_get_bits8(&gb, header.data, header.size);  // line 1192
```

creates a `GetBitContext` that claims `header.size * 8` bits backed by a pointer
(`header.data`) into the compressed audio packet. The actual usable bytes from
`header.data` to end of the packet allocation (including AV_INPUT_BUFFER_PADDING_SIZE)
is far smaller than `header.size`. Any `get_bits()` call that advances past the
real allocation triggers an OOB heap read via:

```c
AV_RL32(gb->buffer + (gb->index >> 3))  // reads 4 bytes beyond real buffer
```

## Attack Structure

### QDCA Extradata (MOV stsd → wave atom)
| Field          | Value | Purpose                          |
|----------------|-------|----------------------------------|
| checksum_size  | 4     | Minimum valid (> 1); keeps packet tiny |
| fft_size       | 64    | fft_order = 7 (in valid range [7,9]) |
| group_size     | 512   | frame_size = 32 ≤ 512 |
| channels       | 2     | stereo |
| samplerate     | 44100 | Hz |

### Audio Packet (4 bytes in mdat)
```
Byte 0: 0x83  → outer type = 3 (no checksum), bit7 set → 2-byte size follows
Byte 1: 0xFF  → size high
Byte 2: 0xFF  → size low  →  header.size = 0xFFFF = 65535
Byte 3: 0x0D  → first byte of header.data (inner type 13 = fft_level_exp)
```

### Decode Flow
1. `qdm2_decode_frame()` receives 4-byte packet, calls `qdm2_decode()` 16×
2. On sub_packet=0: `qdm2_decode_super_block()` is called
3. `init_get_bits8(&outer_gb, packet, 4)` → 32 bits outer GB
4. `qdm2_decode_sub_packet_header()` reads 3 bytes: type=3, size=65535
5. `header.data = &packet[3]` (1 real byte + 64 padding = 65 total accessible)
6. **`init_get_bits8(&gb, header.data, 65535)`** ← VULNERABLE CALL
   - Claims 65535×8 = 524280 bits
   - Only 65 bytes = 520 bits actually accessible
   - Mismatch ratio: 1008×
7. Inner loop (type 13): reads fft_level_exp from gb → accesses padding bytes

### Buffer Layout (with ASAN)
```
packet[0..3]   = 0x83 0xFF 0xFF 0x0D  ← real data (4 bytes)
packet[4..67]  = 0x00 * 64            ← AV_INPUT_BUFFER_PADDING_SIZE zeros
packet[68+]    = ASAN REDZONE         ← heap-buffer-overflow detected here
                                         if index reaches bit 520+
```

The inner loop with type-13 sub-packet reads 6×6 = 36 bits from positions
16..51 of header.data (bytes 2..6), which are all in the padding zone.
**Mathematical proof that ASAN cannot be triggered with standard AVPacket allocation:**

For any inner sub-packet at position P in header.data with declared size S:
- Not-truncated constraint: S + header_bytes ≤ packet_bytes ≤ checksum_size - outer_hdr_bytes
  → S ≤ checksum_size - outer_hdr_bytes - header_bytes ≤ checksum_size - 5
- OOB condition: S > (checksum_size + AV_INPUT_BUFFER_PADDING_SIZE) - (outer_hdr_bytes + P)
  = checksum_size + 64 - outer_hdr_bytes - P
  ≥ checksum_size + 64 - outer_hdr_bytes - (checksum_size - 5)  [since P ≤ S + header_bytes ≤ checksum_size - 5]
  = 69 - outer_hdr_bytes ≥ 66

These two conditions combine to: S must simultaneously be ≤ checksum_size - 5  AND > checksum_size + 59.
This requires -5 > 59 → impossible. The 64-byte AV_INPUT_BUFFER_PADDING_SIZE closes the gap exactly.

The same analysis applies to the inner loop's bit-index walk: the bit index must advance past
`(checksum_size + 64 - outer_hdr_bytes) * 8` bits to trigger OOB. Doing so requires enough
iterations, each driven by non-zero type bytes in real packet data. But every such type byte
requires checksum_size to be larger (to include it as real data), which proportionally grows
the allocation and pushes the OOB boundary further out. The gap is always 64 bytes (the padding).

## Files
- `vuln_001_gen.py` — generates `vuln_001_input.mov`
- `vuln_001_run.sh` — runs ffmpeg and captures output
- `vuln_001_input.mov` — crafted MOV file (generated)
- `vuln_001_result.txt` — ffmpeg output (generated)
- `vuln_001_status.txt` — verification verdict
