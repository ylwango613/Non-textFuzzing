# VULN 001: OOB Heap Read in get_cap() via Untrusted Pcap Bitmask

## Vulnerability Summary

- **File**: `libavcodec/jpeg2000dec.c`
- **Function**: `get_cap()`
- **Lines**: 455-464
- **CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause

`get_cap()` verifies only that at least 6 bytes remain before reading the CAP marker payload (line 455). It then reads 4 bytes for the `Pcap` field unconditionally (line 460), leaving a minimum of 2 bytes. The subsequent `for` loop (lines 462-464) calls `bytestream2_get_be16u()` — which expands to `AV_RB16(g->buffer); g->buffer += 2` with **no bounds check** — once for every bit set in `Pcap`. With `Pcap = 0xFFFFFFFF` (all 32 bits set), the loop attempts to read 32 × 2 = 64 bytes of `Ccap` values when only 2 bytes are available.

## Trigger Path

```
ffmpeg -i <crafted.jp2> -f null -
  → avformat_open_input()
  → avcodec_decode_video2() / jpeg2000_decode_frame()
  → jpeg2000_read_main_headers()
  → get_cap()      ← OOB read here
```

## PoC Approach

The generated JP2/J2K file contains:
1. A valid JP2 container with SOC marker.
2. A **CAP marker** (`0xFF50`) with:
   - `Lsiz = 8` (marker length field, includes 2 bytes for itself → 6 bytes payload)
   - `Pcap = 0xFFFFFFFF` (all 32 bits set)
   - `Ccap[0] = 0x0000` (only 1 Ccap word fits in the 6-byte payload: 4 Pcap + 2 Ccap)
3. Immediately followed by the SIZ marker and EOC.

The CAP marker passes the `>= 6` check (exactly 6 bytes remain in the marker payload). After reading the 4-byte `Pcap`, only 2 bytes remain. But the loop iterates 32 times (one per set bit), so 31 additional 2-byte reads go out of bounds.

## Expected Behavior with ASAN

- `heap-buffer-overflow` detected by AddressSanitizer on the second (or later) iteration of the `bytestream2_get_be16u` loop inside `get_cap()`.
- The read overflows past the allocated heap buffer for the packet data.

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Generates `vuln_001_input.jp2` and `vuln_001_input.j2k` |
| `vuln_001_run.sh` | Runs ffmpeg with ASAN against both files |
| `vuln_001_result.txt` | Output from ffmpeg + ASAN log |
| `vuln_001_status.txt` | VERIFIED_CRASH / VERIFIED_BEHAVIOR / UNVERIFIED / ERROR |
