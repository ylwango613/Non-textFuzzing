# VULN 002: Heap OOB Read — mjpega_dump_header.c

## Location
`libavcodec/bsf/mjpega_dump_header.c`, line 83

## Vulnerable Code
```c
case APP1:
    if (i + 8 < in->size && AV_RL32(in->data + i + 8) == AV_RL32("mjpg")) {
```

## Root Cause
The guard `i + 8 < in->size` only ensures that `in->data[i+8]` is within
bounds (index i+8 is valid when size > i+8, i.e. size >= i+9).

However, `AV_RL32(in->data + i + 8)` reads **4 bytes** starting at offset i+8,
accessing indices i+8, i+9, i+10, i+11. The correct guard should be
`i + 11 < in->size` (i.e., size >= i+12).

**Worst case (3 bytes OOB):** `in->size == i + 9`
- i+8 < i+9 → True (guard passes)
- AV_RL32 reads [i+8, i+9, i+10, i+11]: only i+8 is valid → 3 bytes OOB

## PoC Strategy

The crafted MJPEG packet places the APP1 marker (0xFF 0xE1) at byte position `p`
and truncates the packet at `p + 9` bytes total:

```
[FF D8]              SOI (positions 0-1)
[FF E1]              APP1 marker (positions p, p+1)  — e.g. p=2
[00 00 00 00 00 00 00]  7 padding bytes (positions p+2 .. p+8)
                       --- PACKET ENDS HERE (size = p+9) ---
```

When the BSF scans this packet:
1. Loop reaches i=p, sees `in->data[p]=0xFF`, `in->data[p+1]=0xE1` → APP1 case
2. Guard: `p+8 < p+9` → True
3. `AV_RL32(in->data + p+8)` reads 4 bytes at [p+8 .. p+11]
4. Only p+8 is within the allocated buffer; p+9, p+10, p+11 are **out of bounds**

## Trigger Command
```bash
ffmpeg -f mjpeg -i vuln_002_input.mjpeg -bsf:v mjpegadump -f null -
```

The `-f mjpeg` flag forces the MJPEG demuxer, which will pass the raw packet
bytes directly to the mjpegadump BSF.

## Files Generated
| File | APP1 Position | Packet Size | OOB Bytes |
|------|--------------|-------------|-----------|
| `vuln_002_input.mjpeg`        | 2  | 11 | 3 |
| `vuln_002_input_eoi.mjpeg`    | 2  | 13 | 1 |
| `vuln_002_input_struct.mjpeg` | 20 | 29 | 3 |

## Verification Outcome — UNVERIFIED

The BSF **IS** invoked on the malformed packet (confirmed by the log message
`[mjpegadump] could not find SOS marker in bitstream` which appears only after
the APP1 check). The OOB read logically happens, but ASAN does not fire because
`AV_INPUT_BUFFER_PADDING_SIZE = 64` means every packet has 64 extra zeroed bytes
appended to its declared size. For an 11-byte packet the actual allocation is
75 bytes, so bytes at indices 11–13 are still within the allocation.

To trigger a detectable ASAN crash, the OOB would need to exceed 64 bytes past
the packet end — impossible by design. A tool like Valgrind's Memcheck (which
tracks logical rather than allocated boundaries) would catch it.

Working trigger commands:
```bash
# Output BSF with stream copy (two-frame file for probing):
ffmpeg -f mjpeg -i vuln_002_input.mjpeg -c:v copy -bsf:v mjpegadump -f null -

# Input BSF (processes raw demuxed packet before decoder):
ffmpeg -f mjpeg -bsf:v mjpegadump -i vuln_002_input_single.mjpeg -f null -
```

## Fix
Change line 83 from:
```c
if (i + 8 < in->size && AV_RL32(in->data + i + 8) == AV_RL32("mjpg")) {
```
to:
```c
if (i + 11 < in->size && AV_RL32(in->data + i + 8) == AV_RL32("mjpg")) {
```
