# VULN-001: Integer Overflow in ctts Entry Count → Heap Buffer Overflow / OOB Read

## Vulnerability Summary

- **File**: `Bento4/Source/C++/Core/Ap4CttsAtom.cpp`, lines 78-97
- **CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-Based Buffer Overflow) / CWE-125 (Out-of-Bounds Read)

## Root Cause

In `AP4_CttsAtom::AP4_CttsAtom(...)`:

1. **Line 78**: `entry_count` is read as `AP4_UI32` (32-bit unsigned int) from the file stream.
2. **Line 80**: `new unsigned char[entry_count * 8]` — multiplication done in 32-bit arithmetic.
   - If `entry_count = 0x20000000`, then `0x20000000 * 8 = 0x100000000 mod 2^32 = 0`
   - Result: a 0-byte buffer is allocated.
3. **Line 81**: `stream.Read(buffer, 0)` reads 0 bytes → returns `AP4_SUCCESS`, bypassing error check.
4. **Lines 89-96 (loop)**: Loop iterates `entry_count` (536,870,912) times accessing `buffer[i*8]` and `buffer[i*8+4]` on the 0-byte buffer → heap OOB read.

## Trigger Condition

Craft a ctts atom with `entry_count = 0x20000000` (big-endian bytes: `\x20\x00\x00\x00`).

## ctts Atom Layout

```
size(4BE) | 'ctts'(4) | version(1=0) | flags(3=0) | entry_count(4BE=0x20000000)
```

Total atom size: 16 bytes (no actual entry data needed).

## PoC Files

- `vuln_001_gen.py` — Python script that generates the malicious MP4
- `vuln_001_run.sh` — Shell script that generates and runs the PoC
- `vuln_001.mp4` — The generated malicious MP4 file
- `vuln_001_result.txt` — ASAN/program output from the run
- `vuln_001_status.txt` — Crash verification status

## Expected Crash

- **ASAN**: `heap-buffer-overflow` on 0-byte buffer at first loop iteration
- **Alternative**: `bad_alloc` / allocation-size-too-big if `m_Entries.SetItemCount(0x20000000)` is reached first
- **Signal**: SIGABRT or SIGSEGV

## MP4 Structure

```
ftyp
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr
      minf
        smhd
        dinf
          dref
        stbl
          stsd
          stts
          stsc
          stsz
          stco
          ctts  <-- entry_count = 0x20000000
mdat
```
