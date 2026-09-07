# VULN 002 — stz2 table_size Integer Overflow → Heap OOB Read

## Vulnerability Summary

- **Binary**: `mp42aac` (Bento4, ASAN+UBSAN build)
- **Function**: `AP4_Stz2Atom::AP4_Stz2Atom()` (Ap4Stz2Atom.cpp:89-120)
- **Type**: Integer overflow → heap out-of-bounds read

## Root Cause

When parsing an `stz2` box with `field_size=16` and `sample_count=0x10000001`:

```
table_size = (sample_count * m_FieldSize + 7) / 8
           = (0x10000001 * 16 + 7) / 8
```

The multiplication `0x10000001 * 16` is performed in 32-bit arithmetic, producing `0x100000010`, which wraps to `0x10 = 16`. The computed `table_size = (16 + 7) / 8 = 2`.

The size check `(table_size + 8) > size` compares 10 against the box size (20 bytes), so it passes. A 2-byte buffer is allocated, but then:

1. `m_Entries.SetItemCount(0x10000001)` tries to allocate ~512 MB for 268 million uint16 entries (bad_alloc / DoS on memory-limited systems).
2. If allocation succeeds, the loop `buffer[i*2]` for `i = 0 .. 0x10000001-1` reads far beyond the 2-byte buffer — heap OOB read detected by ASAN.

## PoC Approach

`vuln_002_gen.py` constructs a minimal but structurally valid MP4 file:

- `ftyp` box (mp42 brand)
- `moov` containing `mvhd` + `trak`
  - `trak` contains `tkhd` + `mdia`
    - `mdia` contains `mdhd` + `hdlr` + `minf`
      - `minf` contains `smhd` + `dinf` (with self-contained `url `) + `stbl`
        - `stbl` contains `stsd` (mp4a) + `stts` + **`stz2`** + `stco`

The malicious `stz2` box:
- `version=0`, `flags=0`
- `reserved=0x000000`, `field_size=16`
- `sample_count=0x10000001`
- **Zero** actual sample entries in the payload

Total `stz2` box size = 20 bytes (just the header, no table data).

## Expected Behavior

| Scenario | Expected ASAN/result |
|---|---|
| Low memory | `std::bad_alloc` or OOM kill (DoS) |
| Sufficient memory | `ERROR: AddressSanitizer: heap-buffer-overflow` on the OOB read |
| UBSAN | `runtime error: signed integer overflow` on the multiplication |

Any of these outcomes confirms the vulnerability is triggerable.

## Files

| File | Purpose |
|---|---|
| `vuln_002_gen.py` | Generates `vuln_002.mp4` with malicious `stz2` |
| `vuln_002_run.sh` | Runs the PoC and captures ASAN output |
| `vuln_002.mp4` | Generated malicious input |
| `vuln_002_result.txt` | Combined stdout/stderr + ASAN log |
| `asan_002.log.*` | Raw ASAN/UBSAN log file(s) |
| `vuln_002_status.txt` | Verification result |
