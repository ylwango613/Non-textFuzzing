# VULN-002 Notes: AP4_ObjectDescriptor SubStream Integer Underflow

## Vulnerability Summary

**Location**: `Bento4/Source/C++/Core/Ap4ObjectDescriptor.cpp`, lines 93-96 and 252-255

**Root cause**: Unsigned integer underflow in substream size computation.

```cpp
// AP4_ObjectDescriptor constructor (line 93-96):
AP4_Position offset;
stream.Tell(offset);
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size - AP4_Size(offset-start));
```

When `payload_size = 0` and the constructor has already read N bytes from the stream
(so `offset - start = N`), the expression `0 - N` wraps around to `2^32 - N`, creating
a ~4 GB virtual substream.

## Affected Constructors

### AP4_ObjectDescriptor (tag=0x01 or 0x11)
- Reads 2 bytes: `ReadUI16(bits)` for ObjectDescriptorId + url_flag
- Underflow: `0 - 2 = 0xFFFFFFFE` (4294967294, ~4 GB substream)

### AP4_InitialObjectDescriptor (tag=0x02 or 0x10)
- Reads 2 bytes: `ReadUI16(bits)` for id + url_flag
- If `url_flag == 0`: reads 5 more bytes (profile level indicators)
- Total: 7 bytes read
- Underflow: `0 - 7 = 0xFFFFFFF9` (4294967289, ~4 GB substream)

## Tag Constants (from Ap4ObjectDescriptor.h)

```
AP4_DESCRIPTOR_TAG_OD      = 0x01  -> AP4_ObjectDescriptor
AP4_DESCRIPTOR_TAG_IOD     = 0x02  -> AP4_InitialObjectDescriptor
AP4_DESCRIPTOR_TAG_MP4_IOD = 0x10  -> AP4_InitialObjectDescriptor  (used in PoC)
AP4_DESCRIPTOR_TAG_MP4_OD  = 0x11  -> AP4_ObjectDescriptor
```

## Trigger Path

```
mp42aac main()
  AP4_File(stream)
    ParseStream()
      AP4_IodsAtom::Create(size, stream)
        AP4_DescriptorFactory::CreateDescriptorFromStream(stream, descriptor)
          reads tag=0x10, expandable_size=0x00 → payload_size=0, header_size=2
          new AP4_InitialObjectDescriptor(stream, 0x10, header_size=2, payload_size=0)
            stream.Tell(start)
            stream.ReadUI16(bits)           # consumes 2 bytes
            stream.ReadUI08 × 5             # consumes 5 bytes (if url_flag=0)
            stream.Tell(offset)             # offset - start = 7
            payload_size - (offset-start) = 0 - 7 = 0xFFFFFFF9  *** UNDERFLOW ***
            new AP4_SubStream(stream, offset, 0xFFFFFFF9)
```

## Why No ASAN/UBSAN Output Observed

1. **UBSAN default set** (`-fsanitize=undefined`) instruments *signed* integer overflow
   (`__ubsan_handle_sub_overflow`), NOT unsigned integer wrap-around. Unsigned arithmetic
   is defined behavior in C/C++, so `0u - 7u = 0xFFFFFFF9u` is not flagged.

2. **ASAN** detects heap/stack OOB, use-after-free, etc. The huge `AP4_SubStream`
   (`size=0xFFFFFFF9`) delegates reads to `AP4_FileByteStream`. The file stream
   returns `AP4_ERROR_EOS` as soon as it reaches the end of file; no heap allocation
   is overrun.

3. **Secondary loop** inside the OD/IOD constructor reads garbage bytes from the file
   as sub-descriptors, but quickly reaches EOF and exits cleanly. No allocator is
   mis-addressed.

## Detection Method Required

To catch this underflow programmatically, one of the following is needed:

- **UBSAN unsigned-integer-overflow** flag:
  `-fsanitize=unsigned-integer-overflow` (add to build)
  Would fire: `runtime error: unsigned integer overflow: 0 - 7 cannot be represented`

- **Static analysis** (e.g., Coverity CWE-191, CodeChecker, cppcheck --signed-overflow)

- **Fuzzing** with an input where the corrupt substream leads to a larger allocation
  that subsequently overflows (secondary trigger, file-specific)

## PoC Design

The crafted MP4 contains:
- `ftyp` + `moov` with a minimal `mvhd`
- `iods` FullBox with a single `MP4_IOD` descriptor (tag=`0x10`, encoded size=`0x00`)
  followed by 16 null-byte padding bytes
- The padding ensures `ReadUI16` and the 5 `ReadUI08` calls all succeed, so `offset-start`
  reaches exactly 7 before the substream is created with size `0xFFFFFFF9`

## Build Info

```
Compiler : g++ (GCC 11)
Build    : Release (-O3 -DNDEBUG)
Sanitizers: -fsanitize=address,undefined -fno-omit-frame-pointer
Binary   : /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac
```
