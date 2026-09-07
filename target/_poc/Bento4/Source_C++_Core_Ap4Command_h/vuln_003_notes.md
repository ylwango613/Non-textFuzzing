# VULN-003 PoC Notes

## Vulnerability Summary

**Title**: AP4_EsDescriptor substream size integer underflow enables OOB descriptor parse  
**CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)  
**File**: `Source/C++/Core/Ap4EsDescriptor.cpp`, line 103  
**Function**: `AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)`

## Root Cause

In `AP4_EsDescriptor.cpp` line 103:
```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                 payload_size - AP4_Size(offset - start));
```

The constructor reads unconditionally:
- `ReadUI16(m_EsId)` — 2 bytes
- `ReadUI08(bits)` — 1 byte

These consume 3 bytes regardless of `payload_size`. When `payload_size=2`, after those 3 reads, `offset - start = 3`. The subtraction `2 - 3` on `uint32_t` (AP4_Size) wraps to `0xFFFFFFFF` (4 294 967 295).

A `SubStream` is then constructed with `m_Size = 0xFFFFFFFF`, which allows the descriptor parser loop (`while AP4_DescriptorFactory::CreateDescriptorFromStream`) to read far beyond the ES descriptor boundary into adjacent file data.

## Trigger Path

```
mp42aac input.mp4 /dev/null
  → AP4_File(stream)
    → AP4_AtomFactory parses moov/trak/mdia/minf/stbl/stsd/mp4a
      → AP4_EsdsAtom::Create
        → AP4_DescriptorFactory::CreateDescriptorFromStream (tag=0x03, size=2)
          → AP4_EsDescriptor(stream, header_size=2, payload_size=2)  ← VULNERABLE
            → reads 3 bytes, computes 2-3=0xFFFFFFFF (uint32 underflow)
            → AP4_SubStream(stream, offset, 0xFFFFFFFF)
            → while loop reads adjacent file data as descriptors
```

## PoC Structure

The crafted MP4 has the following structure:
```
ftyp
moov
  mvhd
  trak (audio track, handler='soun')
    tkhd
    mdia
      mdhd
      hdlr
      minf
        smhd
        dinf / dref / url
        stbl
          stsd
            mp4a (AudioSampleEntry)
              esds (EsdsAtom)         <- vulnerable atom
                0x03 0x02 0xAA 0xBB   <- ES_Descriptor tag=3, payload_size=2
                0x00                  <- bits byte (flags=0); ReadUI08 reads this
                0x06 0xFF 0xFF 0xFF 0x7F  <- fake descriptor in overflow SubStream
                                         size encoding → 268 435 455 bytes
          stts / stsc / stsz / stco  (empty)
```

Extra bytes placed after the 2-byte ES_Descriptor payload within the esds atom body:
- Byte 0 (`0x00`): read by `ReadUI08(bits)` — sets flags=0, priority=0
- Bytes 1-5: first descriptor seen by the overflow SubStream — unknown tag `0x06` with MPEG-4 extended size encoding `0xFF 0xFF 0xFF 0x7F` → decoded payload_size = **268 435 455** bytes (~256 MB)
- `AP4_UnknownDescriptor` allocates this via `new AP4_Byte[268435455]` → `std::bad_alloc` crash if system RAM < ~268 MB available

## Variants Generated

| File | payload_size | extra bytes | Expected behaviour |
|------|-------------|-------------|-------------------|
| vuln_003_p2_extra.mp4 | 2 | yes | OOM crash (268 MB alloc) |
| vuln_003_p2_plain.mp4 | 2 | no  | Silent underflow; SubStream reads beyond boundary |
| vuln_003_p1_extra.mp4 | 1 | yes | Larger underflow (0xFFFFFFFE) + OOM attempt |
| vuln_003_p0_extra.mp4 | 0 | yes | Largest underflow (0xFFFFFFFD) + OOM attempt |

## Sanitizer Detection

- **ASAN** (`-fsanitize=address`): indirectly via OOM (`std::bad_alloc` → `abort`) or heap-buffer-overflow if a large descriptor causes writes past an allocated region.
- **UBSAN** (`-fsanitize=undefined`): the unsigned integer underflow `2-3` on `uint32_t` is technically *defined* behaviour (wraps), so default UBSAN does **not** flag it directly. Adding `-fsanitize=unsigned-integer-overflow` would catch line 103 explicitly.
- **Crash path**: `std::bad_alloc` thrown by `new AP4_Byte[268435455]` inside `AP4_DataBuffer::ReallocateBuffer` propagates uncaught → `std::terminate` → `SIGABRT` (exit 134).

## Fix Recommendation

Add a bounds check before constructing the SubStream:
```cpp
AP4_Size consumed = (AP4_Size)(offset - start);
if (consumed > payload_size) {
    // Malformed descriptor: payload_size smaller than required fields
    substream->Release();
    return;  // or set an error flag
}
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                 payload_size - consumed);
```
