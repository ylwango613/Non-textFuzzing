# VULN 004 PoC Notes

## Vulnerability
**Location**: `Bento4/Source/C++/Core/Ap4StssAtom.cpp` — `AP4_StssAtom::AP4_StssAtom(AP4_UI32, AP4_ByteStream&)`

**Root Cause**: The stss atom is a *full atom* (12-byte header: size+type+version+flags) but the
bounds check uses `AP4_ATOM_HEADER_SIZE` (8) instead of `AP4_FULL_ATOM_HEADER_SIZE` (12). This
allows a box with `size=16, entry_count=1` to pass the check even though the box contains zero
bytes of actual entry data.

**Correct check** (should use 12-byte full-atom header):
```
available = (16 - 12 - 4) / 4 = 0  <  1  → REJECT
```

**Actual check** (uses 8-byte base-atom header — the bug):
```
available = (16 -  8 - 4) / 4 = 1  >= 1  → PASSES (BUG)
```

## PoC Strategy

### File layout
```
ftyp (16 B)
moov
  mvhd (108 B)
  trak
    tkhd (92 B)
    mdia
      mdhd (32 B)
      hdlr
      minf
        smhd (16 B)
        dinf / dref / url
        stbl
          stsd  (entry_count=0)
          stts  (entry_count=1: sample_count=1, delta=1)
          stsc  (entry_count=1: chunk=1, spc=1, sdi=1)
          stsz  (sample_size=0, count=1, entry=4)
          stss  ← MALICIOUS: size=16, entry_count=1, NO entry bytes
          stco  ← placed immediately after stss
```

### OOB read mechanism
After the malicious stss box (exactly 16 bytes) the stream cursor sits at the first byte of the
stco box. The buggy code allocates a 1-element array and calls `stream.Read(buffer, 4)`, reading
the 4-byte big-endian size field of stco (value = 20 = 0x00000014) and storing it as
`m_Entries[0]` — a sync sample number that was never written in the file.

### Expected Outcome
This is a **logical / semantic OOB** read at the file-stream level, not a C++ heap/stack
out-of-bounds access. ASAN will not report a crash because the `Read()` call is operating on a
legitimate file buffer and the destination array was properly allocated. The expected observable
effect is:

- mp42aac processes the file without an ASAN crash signal.
- The stss table contains one entry (sync sample number = 20) that was fabricated from stco data.
- The output result file will likely show normal exit or a graceful parse warning.
- Status: **UNVERIFIED** (logic bug, not a memory-safety violation catchable by ASAN).

### Verification approach
To verify the logic bug independently, inspect the parsed stss entry values with a Bento4 debug
build or `mp4dump`: the reported sync sample number should equal the big-endian integer formed by
the first 4 bytes of the stco box (i.e., stco's size field) rather than any value written inside
the stss box.
