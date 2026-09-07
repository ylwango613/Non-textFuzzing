# VULN 001: Integer Underflow in AP4_ObjectDescriptor Substream Size

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4ObjectDescriptor.cpp`  
**Location**: `AP4_ObjectDescriptor::AP4_ObjectDescriptor` (lines 94-96)

```cpp
AP4_Position offset;
stream.Tell(offset);
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
    payload_size - AP4_Size(offset - start));  // <-- unsigned underflow
```

When an OD descriptor (tag `0x01`) has `url_flag=1`, the constructor reads:
- 2 bytes: `bits` field
- 1 byte: `url_length`
- `url_length` bytes: URL data

If `2 + 1 + url_length > payload_size` (both unsigned `AP4_Size` = `uint32_t`), the
subtraction underflows: e.g., `5 - 203 = 4294967098` (~4 GB). The resulting
`AP4_SubStream` has a declared size of ~4 GB, causing it to read far past the actual
data bounds of the file stream.

## Trigger Approach

Craft an `iods` FullBox inside `moov` containing:
- Expandable descriptor: tag `0x01`, declared payload_size `5` (single byte `0x05`)
- Payload bytes written in file: `bits(2B, url_flag=1)` + `url_length=200(1B)` + `200B URL`
  - Total bytes actually written: 203, vs declared payload_size=5
- `mdat` box follows with 256 zero-bytes providing data for the unbounded substream to read

When `mp42aac` parses this file:
1. `AP4_IodsAtom::Create` → `AP4_DescriptorFactory::CreateDescriptorFromStream`
2. Reads tag=`0x01`, payload_size=`5`
3. Calls `AP4_ObjectDescriptor(stream, tag=0x01, header_size=2, payload_size=5)`
4. Reads 203 bytes from stream (2+1+200)
5. `payload_size - (offset-start)` = `5 - 203` → unsigned underflow → ~4 GB
6. Creates `AP4_SubStream` with ~4 GB size → out-of-bounds read

## Expected ASAN Output

- `heap-buffer-overflow` or `global-buffer-overflow` in `AP4_SubStream` or descriptor parsing
- Or `SEGV` on a NULL/wild pointer dereference during the unbounded descriptor iteration
- Stack trace should include `AP4_ObjectDescriptor::AP4_ObjectDescriptor`,
  `AP4_DescriptorFactory::CreateDescriptorFromStream`, and `AP4_IodsAtom`
