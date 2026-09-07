# VULN 002 - Integer Underflow in AP4_EsDescriptor

## Vulnerability Location

**File**: `Bento4/Source/C++/Core/Ap4EsDescriptor.cpp`
**Lines**: 66–110 (constructor reading from stream), critical underflow at line 102–103

## Root Cause

The `AP4_EsDescriptor` constructor unconditionally reads:
- `ES_ID`  → 2 bytes
- `flags`  → 1 byte
= **3 bytes total** before checking how many remain.

At lines 100–103 it computes the sub-descriptor sub-stream size:
```cpp
AP4_Position offset;
stream.Tell(offset);                                    // offset = start + 3
AP4_SubStream* substream = new AP4_SubStream(stream,
    offset,
    payload_size - AP4_Size(offset - start));          // 2 - 3 = 0xFFFFFFFF!
```

When `payload_size` < 3 (we use `payload_size = 2`), the subtraction
`payload_size - AP4_Size(offset - start)` underflows from the **unsigned 32-bit**
perspective:

```
2 (uint32) - 3 (uint32) = 0xFFFFFFFF = 4,294,967,295
```

The resulting `AP4_SubStream` has an effective size of **4 GB**, which disables
the boundary clamp inside `ReadPartial`. The descriptor factory loop at lines
105–109 then reads arbitrarily far beyond the declared ES_Descriptor boundary
into adjacent boxes (stts, stsc, stsz, stco), then into mdat, and ultimately
to the end of the file.

## Trigger Path

```
mp42aac
  └─ AP4_File constructor
       └─ AP4_AtomFactory → AP4_EsdsAtom::Create()
            └─ AP4_DescriptorFactory::CreateDescriptorFromStream(tag=0x03)
                 └─ new AP4_EsDescriptor(stream, header_size=2, payload_size=2)
                      │  start = Tell()
                      │  ReadUI16(ES_ID)   → +2 bytes
                      │  ReadUI08(flags)   → +1 byte  ← OOB read #1 (byte 3 of a 2-byte payload)
                      │  offset = Tell()   → start + 3
                      │  payload_size(2) - AP4_Size(3) = 0xFFFFFFFF   ← UNDERFLOW
                      └─ SubStream(stream, offset, 0xFFFFFFFF)
                           └─ factory loop reads to EOF of file (OOB read #2+)
```

## Crafted File Layout (vuln_002.mp4)

The esds box payload is constructed as follows (relative to the start of the
esds FullBox's descriptor area):

| Byte | Value | Role |
|------|-------|------|
| +0   | 0x03  | ES_Descriptor tag |
| +1   | 0x02  | **payload_size = 2** (underflow trigger) |
| +2   | 0x00  | ES_ID high (declared payload byte 1) |
| +3   | 0x01  | ES_ID low  (declared payload byte 2) |
| +4   | 0x00  | **flags** — read *outside* declared 2-byte payload (OOB #1) |
| +5   | 0x05  | ← SubStream byte 0: fake DecoderSpecificInfo tag |
| +6   | 0x02  | VLE size = 2 |
| +7   | 0x11  | DSI byte 0 (AAC-LC @44100 Hz marker) |
| +8   | 0x90  | DSI byte 1 (stereo) |
| +9…  | 0x00* | padding; also read by factory through file adjacency |

Bytes at +5 onward are also within the esds box boundary but outside the
ES_Descriptor's declared payload. The outer `AP4_EsdsAtom` parser correctly
seeks past the esds box, but by that time the `AP4_EsDescriptor` constructor
has already spawned the unbounded sub-stream and consumed adjacent file data.

## Impact

1. **Out-of-bounds read**: the descriptor factory reads from arbitrary file
   positions (stts, stsc, stsz, stco, mdat …) interpreting them as
   MPEG-4 descriptor tag/size pairs.
2. **Memory allocation**: each "parsed" descriptor allocates a buffer sized by
   the VLE value found in the adjacent data. A crafted file can cause very
   large allocations leading to OOM / `std::bad_alloc`.
3. **Logic corruption**: `AP4_EsDescriptor::m_SubDescriptors` is populated
   with garbage descriptors. Downstream code expecting valid DecoderConfig
   sub-descriptors may dereference NULL or access freed memory.

## Reproduction

```bash
python3 vuln_002_gen.py
./vuln_002_run.sh
cat vuln_002_result.txt
```
