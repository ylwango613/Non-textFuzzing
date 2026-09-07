# VULN 001 - Heap OOB Read in AP4_Dec3Atom::AP4_Dec3Atom()

## Summary
- **CWE**: CWE-125 (Out-of-bounds Read)
- **File**: Bento4/Source/C++/Core/Ap4Dec3Atom.cpp
- **Lines**: 96-99
- **Binary**: mp42aac (ASAN+UBSAN build)

## Root Cause

The `AP4_Dec3Atom` constructor parses EC3-specific box payload using raw pointer
arithmetic and a shrinking `payload_size` counter.

After consuming the 2-byte EC3 header:
```
payload     += 2;
payload_size -= 2;   // payload_size == 3 when dec3 box size == 13
```

The per-substream parsing loop checks:
```cpp
if (payload_size < 3) {  // 3 is NOT < 3, so this guard is skipped
    ...
    continue;
}
// reads payload[0], [1], [2]  (valid)
m_SubStreams[i].num_dep_sub = (payload[2]>>1) & 0xF;
if (m_SubStreams[i].num_dep_sub) {
    m_SubStreams[i].chan_loc = (payload[2]<<7 | payload[3]) & 0x1F;  // payload[3] OOB!
    payload      += 4;
    payload_size -= 4;   // 3 - 4 = 0xFFFFFFFF (unsigned underflow)
}
```

When `payload_size == 3` and `num_dep_sub != 0`, `payload[3]` reads one byte
beyond the allocated buffer. The subsequent unsigned underflow of `payload_size`
can then allow up to 8 further substream iterations to bypass the `< 3` check.

## Trigger Conditions

1. A `dec3` box with `size = 13` (8-byte header + 5-byte payload).
2. EC3 header bytes `[0x00, 0x00]`: `num_ind_sub = 0` → exactly 1 substream.
3. Payload byte `[4] = 0x0E`: `num_dep_sub = (0x0E>>1)&0xF = 7` (nonzero).
4. This causes the read of `payload[3]` which is 1 byte past the allocated buffer.

## PoC MP4 Structure

```
ftyp (24 bytes)
moov (490 bytes)
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr (soun)
      minf
        smhd
        dinf > dref > url
        stbl
          stsd
            ec-3 (AudioSampleEntry, 49 bytes)
              dec3 (size=13, payload=[00 00 00 00 0E])
          stts, stsc, stsz, stco (all empty)
mdat (8 bytes, empty)
```

## dec3 Payload Byte Layout (5 bytes)

| Offset | Value | Purpose |
|--------|-------|---------|
| 0 | 0x00 | data_rate MSBs = 0 |
| 1 | 0x00 | data_rate LSBs + num_ind_sub=0 (→ 1 substream) |
| 2 | 0x00 | fscod=0, bsid=0, bsmod_msb=0 |
| 3 | 0x00 | bsmod rem., acmod=0, lfeon=0 |
| 4 | 0x0E | **num_dep_sub=(0x0E>>1)&0xF=7 → OOB trigger** |

## Expected ASAN Output

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 ... AP4_Dec3Atom::AP4_Dec3Atom(...)
       Ap4Dec3Atom.cpp:97
```

## Files

- `vuln_001_gen.py` — generates `vuln_001.mp4`
- `vuln_001_run.sh`  — runs the PoC and captures output
- `vuln_001.mp4`     — the malicious MP4 file (generated)
- `vuln_001_result.txt` — captured output (generated)
- `vuln_001_status.txt` — VERIFIED_CRASH / UNVERIFIED / ERROR
