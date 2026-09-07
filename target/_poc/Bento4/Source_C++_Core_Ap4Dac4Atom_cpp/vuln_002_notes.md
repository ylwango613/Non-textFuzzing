# VULN 002: Integer Underflow in AP4_Dac4Atom::Create

## Vulnerability

- **File**: `Bento4/Source/C++/Core/Ap4Dac4Atom.cpp`, lines 49–51
- **CWE**: CWE-191 (Integer Underflow / Wraparound)
- **Binary**: `mp42aac`

## Root Cause

```cpp
// Ap4Dac4Atom.cpp:49-51
unsigned int payload_size = size - AP4_ATOM_HEADER_SIZE;  // AP4_ATOM_HEADER_SIZE = 8
AP4_DataBuffer payload_data(payload_size);
AP4_Result result = stream.Read(payload_data.UseData(), payload_size);
```

`size` is taken directly from the 4-byte size field of the `dac4` ISO BMFF box in the
MP4 file. There is no guard ensuring `size >= 8`.

When `size = 4` (less than AP4_ATOM_HEADER_SIZE=8):
- `payload_size = 4 - 8 = 0xFFFFFFF8` (unsigned 32-bit wrap-around, ~4 GB)
- `AP4_DataBuffer(0xFFFFFFF8)` requests ~4 GB from the allocator
- Causes `std::bad_alloc`, OOM kill, or memory exhaustion

## Trigger Conditions

The `dac4` (AC-4 Decoder Specific Info) box is a child atom that lives inside an
MP4 audio sample entry.  To reach `AP4_Dac4Atom::Create`, the parser must walk:

```
moov → trak → mdia → minf → stbl → stsd → mp4a → dac4
```

## PoC Approach

`vuln_002_gen.py` uses only Python's `struct` module to assemble a minimal but
structurally valid MP4 file.  The file follows the standard ISOBMFF hierarchy so
Bento4 parses through to the `stsd` sample description and processes the `mp4a`
audio sample entry and its child atoms.

The malformed `dac4` box is injected as a child of the `mp4a` sample entry:

```
dac4_box = b'\x00\x00\x00\x04' + b'dac4'
             ↑ size = 4           ↑ type
```

Physically 8 bytes are written.  The parser reads `size=4`, reads `type="dac4"`,
then calls `AP4_Dac4Atom::Create(4, stream)`.  The underflow happens immediately
inside `Create()` before any stream seeking occurs.

## Full MP4 Structure

```
ftyp  (mp42)
moov
  mvhd
  trak
    tkhd  (flags=3: enabled + in-movie)
    mdia
      mdhd  (timescale=44100)
      hdlr  (soun)
      minf
        smhd
        dinf
          dref  (url, self-contained)
        stbl
          stsd
            mp4a  ← audio sample entry
              dac4  [size=4, MALFORMED → triggers underflow in Create()]
          stts  (empty)
          stsc  (empty)
          stsz  (empty)
          stco  (empty)
```

## Expected Crash Behaviour

| Environment | Expected outcome |
|-------------|-----------------|
| Plain binary | `std::bad_alloc` exception → abnormal termination |
| ASAN build   | Allocator OOM error or `std::bad_alloc` reported |
| Low-memory system | OOM killer terminates the process |

## Fix

Add a bounds check before the subtraction:

```cpp
if (size < AP4_ATOM_HEADER_SIZE) return NULL;
unsigned int payload_size = size - AP4_ATOM_HEADER_SIZE;
```
