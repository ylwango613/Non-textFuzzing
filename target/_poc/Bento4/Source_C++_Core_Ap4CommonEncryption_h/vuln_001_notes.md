# vuln_001 – SENC OVERRIDE Flag Payload-Size Undercomputation → OOB/Crash

## What the PoC Does

`vuln_001_gen.py` builds a fragmented MP4 file containing:

- A `ftyp` box (file-type declaration)
- A minimal `moov` box with `mvhd` (movie header, no audio track needed)
- A `moof` box containing `mfhd` + `traf`, where `traf` holds:
  - `tfhd` (track fragment header)
  - A `senc` full atom with **size field = 12** (header-only, no content bytes)
    and **flags = 0x000001** (OVERRIDE flag set), followed immediately by
    32 canary bytes in the raw stream so the override-field reads don't hit EOF
- A `mdat` box with dummy payload

## Why It Triggers the Vulnerability

In `Ap4CommonEncryption.cpp` (around line 3181–3195), the
`AP4_CencSampleEncryption` constructor:

1. Detects `OVERRIDE_TRACK_ENCRYPTION_DEFAULTS` flag and reads
   **3 + 1 + 16 = 20 bytes** (algorithm_id, per_sample_iv_size, KID) from
   the stream — already crossing the declared 12-byte box boundary.
2. Reads **4 more bytes** for `sample_count` — also outside the box.
3. Computes:
   ```
   payload_size = size − GetHeaderSize() − 4
                = 12 − 12 − 4
                = 0xFFFFFFFC   (unsigned 32-bit wrap-around / integer underflow)
   ```
4. Calls `m_SampleInfos.SetDataSize(0xFFFFFFFC)` which internally executes
   `new AP4_Byte[0xFFFFFFFC]` — an allocation of ~4 GB.
5. **ASAN reports**: `allocation-size-too-big` (the allocation exceeds ASAN's
   maximum supported size of 0x8000000 bytes).

## Observed ASAN Output

```
==PID==ERROR: AddressSanitizer: requested allocation size 0xfffffffc
  (0x100001000 after adjustments for alignment, red zones etc.)
  exceeds maximum supported size of 0x8000000 (thread T0)
SUMMARY: AddressSanitizer: allocation-size-too-big
  .../asan_new_delete.cpp:102 in operator new[](unsigned long)
```

## Root Cause Summary

The code never subtracts the 20 bytes it consumed for the override fields when
computing `payload_size`. When `size` is at the minimum valid full-atom header
size (12), this subtraction wraps to ~4 GB on unsigned arithmetic. The crash
is therefore deterministic and requires no special OS/memory conditions.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates the crafted `vuln_001.mp4` |
| `vuln_001.mp4` | The trigger input |
| `vuln_001_run.sh` | Runs mp42aac under ASAN and collects output |
| `vuln_001_result.txt` | Combined stdout/stderr + ASAN summary |
| `asan.log.*` | Raw ASAN log(s) |
| `vuln_001_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR verdict |
