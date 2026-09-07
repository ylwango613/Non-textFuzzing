# VULN-001 PoC Notes

## Vulnerability Summary

- **ID**: VULN-001
- **Target**: mp42aac (Bento4)
- **File**: `Source/C++/Core/Ap4CttsAtom.cpp`, lines 77-98
- **CWEs**: CWE-190 (Integer Overflow), CWE-125 (Out-of-bounds Read)

## Root Cause

In `AP4_CttsAtom::AP4_CttsAtom` (the stream-reading constructor):

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);                           // line 78
m_Entries.SetItemCount(entry_count);
unsigned char* buffer = new unsigned char[entry_count*8]; // line 80  ← BUG
AP4_Result result = stream.Read(buffer, entry_count*8);   // line 81
...
for (unsigned i=0; i<entry_count; i++) {                  // line 88
    m_Entries[i].m_SampleCount  = AP4_BytesToUInt32BE(&buffer[i*8  ]); // OOB read
    ...
}
```

`entry_count` is `AP4_UI32` (unsigned 32-bit). The expression `entry_count * 8` is
evaluated as **32-bit** unsigned arithmetic. When `entry_count = 0x20000000`:

```
0x20000000 * 8 = 0x100000000
              → truncated to 32 bits = 0x00000000
```

This means `new unsigned char[0]` is called, allocating a 0-byte (or minimal)
heap buffer. The loop then reads `buffer[i*8]` for `i` in `[0, 0x20000000)`,
causing a massive heap out-of-bounds read on the 0-byte buffer.

Note: `stream.Read(buffer, 0)` succeeds immediately (reads 0 bytes, returns
`AP4_SUCCESS`), so the early-exit guard on line 82 does **not** trigger. The
loop proceeds unconditionally.

## PoC Construction

The crafted MP4 (`vuln_001.mp4`) contains:

```
ftyp (isom)
moov
  mvhd  (version 0, timescale=1000)
  trak
    tkhd  (track_id=1, flags=enabled+in_movie)
    mdia
      mdhd  (timescale=44100)
      hdlr  (handler_type='soun')
      minf
        smhd
        dinf
          dref (url, self-contained)
        stbl
          stsd (empty)
          stts (empty)
          ctts  ← TRIGGER: entry_count = 0x20000000
          stsz (empty)
          stco (empty)
mdat (empty)
```

The ctts box is only 20 bytes:
- 4 bytes: box size (20)
- 4 bytes: box type ('ctts')
- 1 byte:  version (0)
- 3 bytes: flags (0)
- 4 bytes: entry_count (0x20000000)

No actual entry data is needed; the overflow triggers before any entries are read.

## Expected Behavior

When `mp42aac vuln_001.mp4 /dev/null` is run against the ASAN+UBSAN build:

1. The file is opened and atoms are parsed via `AP4_AtomFactory`.
2. `AP4_CttsAtom::Create` is invoked for the ctts box.
3. `entry_count = 0x20000000` is read.
4. `new unsigned char[0x20000000 * 8]` = `new unsigned char[0]` executes.
5. `stream.Read(buffer, 0)` succeeds (reads nothing).
6. The loop begins reading `buffer[0]`, `buffer[8]`, ... up to
   `buffer[0x1FFFFFFF * 8]` — all far outside the 0-byte allocation.
7. **ASAN** reports: `heap-buffer-overflow` (READ) in `AP4_CttsAtom`.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.mp4` using only Python `struct`/`bytes` |
| `vuln_001_run.sh` | Runs gen.py, executes `mp42aac`, collects ASAN output |
| `vuln_001.mp4` | The crafted malicious MP4 (generated at runtime) |
| `vuln_001_result.txt` | Stdout/stderr + ASAN log output (generated at runtime) |
| `asan.log.*` | Raw ASAN log files (generated at runtime) |
| `vuln_001_status.txt` | Final verdict (VERIFIED_CRASH / UNVERIFIED / ERROR) |

## Fix Recommendation

Cast to 64-bit before multiplication:

```cpp
unsigned char* buffer = new unsigned char[(AP4_UI64)entry_count * 8];
```

Or add an explicit bounds check:

```cpp
if (entry_count > (AP4_UI32)((available_size) / 8)) {
    return; // or handle error
}
```
