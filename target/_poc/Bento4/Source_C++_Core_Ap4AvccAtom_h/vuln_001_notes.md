# VULN 001 – AP4_AvccAtom::Create() OOB Heap Read

## Location
- File: `Bento4/Source/C++/Core/Ap4AvccAtom.cpp` (declared in `Ap4AvccAtom.h`)
- Function: `AP4_AvccAtom::Create(AP4_Size size, AP4_ByteStream& stream)`
- Crash line: **75** (`if (payload[0] != 1)`)
- Boundary check: line 80 (`if (payload_size < 6) return NULL;`) — too late

## Vulnerability Class
CWE-125: Out-of-bounds Read (heap)

## Root Cause
```cpp
// line 68
unsigned int payload_size = size - AP4_ATOM_HEADER_SIZE;   // size=8 => 0
AP4_DataBuffer payload_data(payload_size);                  // allocates 0 bytes
stream.Read(payload_data.UseData(), payload_size);          // reads 0 bytes (OK)

const AP4_UI08* payload = payload_data.GetData();
if (payload[0] != 1) { ... }   // LINE 75: read 1 byte from a 0-byte buffer → OOB
// ...
if (payload_size < 6) return NULL;   // LINE 80: check is AFTER the OOB read
```

When `size == 8` (only the box header, no payload), `payload_size` is 0.
The buffer `payload_data` is empty, but `payload[0]` is dereferenced unconditionally
on line 75 before the `payload_size < 6` guard on line 80.

## Trigger Path
```
mp42aac main()
  → AP4_File::AP4_File(stream, ...)
    → AP4_AtomFactory::CreateAtomFromStream()
      → (parses moov → trak → mdia → minf → stbl → stsd → avc1)
        → AP4_AvccAtom::Create(size=8, stream)   ← OOB READ here
```

## PoC Design
The crafted MP4 (`vuln_001.mp4`) contains a minimal but structurally valid
hierarchy that guides the Bento4 parser to the `avcC` atom:

```
ftyp (20 B)
moov
  mvhd  (108 B)
  trak
    tkhd (92 B)
    mdia
      mdhd (32 B)
      hdlr (33 B, handler_type='vide')
      minf
        vmhd (20 B)
        dinf → dref → url_ (36 B)
        stbl
          stsd (entry_count=1)
            avc1                ← sample entry box
              [70 B fields]
              avcC size=8       ← NO payload → OOB read triggered
          stts / stsc / stsz / stco
```

The `avcC` box is crafted with `size=8` (box header only, zero payload bytes).

## Expected Behaviour with ASAN Build
```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 AP4_AvccAtom::Create(...)  Ap4AvccAtom.cpp:75
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow
```

The process may return a non-zero exit code or simply return NULL from Create()
after the OOB byte is read (the check at line 76 will return NULL if
`payload[0] != 1`, and ASAN intercepts the access before or during that read).

## Files
| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Constructs `vuln_001.mp4` with Python `struct` |
| `vuln_001_run.sh` | Runs gen.py then mp42aac, collects ASAN output |
| `vuln_001.mp4` | The malicious MP4 (generated at runtime) |
| `vuln_001_result.txt` | Captured stdout/stderr + ASAN log |
| `vuln_001_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED |
