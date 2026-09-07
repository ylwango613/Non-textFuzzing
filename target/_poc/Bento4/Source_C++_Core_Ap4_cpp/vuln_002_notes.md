# VULN 002 — AP4_CttsAtom Integer Overflow → Heap Buffer Over-read

## Vulnerability Summary

**Location**: `Ap4CttsAtom.cpp`, `AP4_CttsAtom::AP4_CttsAtom()`

**Root cause**: The constructor allocates a read buffer as:
```cpp
unsigned char* buffer = new unsigned char[entry_count * 8];
```
`entry_count` is a `uint32_t`. When `entry_count >= 0x20000000`, the multiplication
`entry_count * 8` wraps around to 0 (integer overflow). A zero-byte heap buffer is
allocated. `stream.Read(buffer, 0)` succeeds trivially (reads nothing).
`m_Entries.SetItemCount(entry_count)` stores the large count. The subsequent loop:
```cpp
for (i = 0; i < entry_count; i++)
    m_Entries[i].m_SampleCount = AP4_BytesToUInt32BE(&buffer[i*8]);
```
reads far out of bounds of the zero-byte allocation — heap buffer over-read.

## PoC Approach

A minimal MP4 is constructed in Python using only `struct` and `bytes` with:
- `ftyp` box (valid MP4 identification)
- `moov` → `trak` → `mdia` → `minf` → `stbl` chain
  - All required sample table boxes (`stsd`, `stts`, `stsc`, `stsz`, `stco`) with `entry_count=0` (empty but valid)
  - Malicious `ctts` box: `entry_count = 0x20000000`, **no actual entry data** (box size = 16 bytes)

The file is just large enough that Bento4's MP4 parser will reach and parse the `ctts`
atom. The malicious `entry_count` triggers the overflow before the read loop executes.

## Expected Behavior

- **With ASAN**: `heap-buffer-overflow` or `heap-buffer-over-read` error reported in
  the ASAN log, along with a stack trace pointing into `AP4_CttsAtom::AP4_CttsAtom`.
- **Without ASAN**: The process may crash with SIGSEGV, produce garbage output, or
  silently corrupt memory depending on heap layout.

## Files

| File | Description |
|------|-------------|
| `vuln_002_gen.py` | Python script that generates `vuln_002.mp4` |
| `vuln_002.mp4` | Malicious MP4 file (generated at runtime) |
| `vuln_002_run.sh` | Shell script to generate and run the PoC under ASAN |
| `vuln_002_result.txt` | Combined stdout/stderr and ASAN log output |
| `vuln_002_status.txt` | Single-line crash verdict |
