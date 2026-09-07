# VULN 002 — OOB Read at num_pic_params in AP4_AvccAtom::Create()

## File
`Bento4/Source/C++/Core/Ap4AvccAtom.cpp`, line 88

## Vulnerability

After the seq-params loop exits, if `cursor == payload_size`, the guard at line 87 (`cursor > payload_size`) evaluates to false (equal is not greater), so execution falls through. Line 88 then reads `payload[cursor]` where `cursor == payload_size`, which is one byte past the end of the heap-allocated buffer — a heap-buffer-overflow read.

```cpp
unsigned int num_pic_params = payload[cursor++];  // LINE 88: OOB when cursor==payload_size
if (cursor > payload_size) return NULL;            // LINE 89: check fires AFTER the read
```

## PoC Strategy

The MP4 file crafts an `avcC` atom with `size=16` (payload = 8 bytes) nested under `moov/trak/mdia/minf/stbl/stsd/avc1/avcC`. The payload bytes are:

| Offset | Value | Meaning |
|--------|-------|---------|
| 0      | 0x01  | version=1 (passes version check at line 75) |
| 1      | 0x4D  | profile |
| 2      | 0x40  | profile_compatibility |
| 3      | 0x0A  | level |
| 4      | 0xFF  | nalu_length_size field |
| 5      | 0xE1  | 0xE0 \| num_seq_params=1 |
| 6–7    | 0x00 0x00 | seq_param_length=0 (zero-length SPS) |

### Execution trace through `AP4_AvccAtom::Create()`:
1. `payload_size = 16 - 8 = 8` (atom size minus header)
2. `payload_size >= 6` — passes check at line 80
3. `num_seq_params = payload[5] & 31 = 1`
4. `cursor = 6`
5. Loop iteration i=0:
   - `cursor+2 = 8 <= 8` — guard passes
   - `cursor += 2 + 0 = 8`
   - `cursor > payload_size` → `8 > 8` = false — passes
6. After loop: `cursor = 8 = payload_size`
7. **Line 88**: `payload[8]` is read — **1 byte past end of 8-byte buffer** → heap-buffer-overflow read

## Expected Output

With an ASAN-instrumented build, the tool should report:
```
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at ...
  #0 ... AP4_AvccAtom::Create(...)
```

## Files

- `vuln_002_gen.py` — generates `vuln_002.mp4`
- `vuln_002_run.sh` — runs the binary and captures ASAN output
- `vuln_002.mp4` — the crafted input
- `vuln_002_result.txt` — combined stdout/stderr + ASAN log
- `asan.log.*` — raw ASAN output files
