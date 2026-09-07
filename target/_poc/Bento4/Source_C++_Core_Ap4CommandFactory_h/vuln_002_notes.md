# VULN 002: Integer Underflow in AP4_InitialObjectDescriptor Substream Size

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4ObjectDescriptor.cpp`, lines 254-255  
**Symbol**: `AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor(AP4_ByteStream&, AP4_UI08, AP4_Size, AP4_Size)`

```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size - AP4_Size(offset - start));
```

`payload_size` and `AP4_Size(offset - start)` are both `AP4_UI32` (unsigned).  
When the number of bytes the constructor actually reads from the stream exceeds
`payload_size`, the subtraction wraps to a very large unsigned value (~4 GB), creating
a SubStream with an almost-unbounded size.  This allows the subsequent descriptor
parsing loop to read far beyond the declared `iods` atom boundary, constituting an
out-of-bounds read.

## Trigger Approaches

### Approach 1 (primary) — `vuln_002.mp4`
- IOD descriptor tag `0x02` inside `moov/iods`
- Expandable-class declared `payload_size = 3`
- `bits` field (2 B) sets `URL_Flag = 0`
- Constructor then reads 5 more profile/level bytes → **7 bytes consumed**
- Underflow: `3 − 7 = 0xFFFFFFFC` (unsigned)

### Approach 2 (secondary) — `vuln_002_alt.mp4`
- Declared `payload_size = 4`
- `bits` field sets `URL_Flag = 1`
- `url_length = 255` → reads 1 + 255 = 256 more bytes → **258 bytes total consumed**
- Underflow: `4 − 258 = 0xFFFFFEFE` (unsigned)

## Expected ASAN / UBSAN Output

- **UBSAN**: `signed integer overflow` or `out-of-bounds` if arithmetic is tracked as signed
- **ASAN heap-buffer-overflow**: if the giant SubStream causes downstream descriptor
  parsing to read off the end of a heap buffer
- **ASAN global-buffer-overflow**: if file data is mmap-backed and reads exceed the mapped region
- At minimum, the binary should process the corrupted `iods` and exit non-zero; the
  SubStream with 0xFFFFFFFC size will iterate over all remaining file data including `mdat`.
