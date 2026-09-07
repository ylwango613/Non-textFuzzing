# VULN 001 – AP4_ObjectDescriptor Substream Size Integer Underflow

## Vulnerability Summary

**CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
**File**: `Source/C++/Core/Ap4ObjectDescriptor.cpp`, lines 74–103
**Function**: `AP4_ObjectDescriptor::AP4_ObjectDescriptor(stream, tag, header_size, payload_size)`

## Root Cause

The stream-reading constructor of `AP4_ObjectDescriptor` performs this sequence:

```cpp
AP4_Position start;
stream.Tell(start);                  // record current position

unsigned short bits;
stream.ReadUI16(bits);               // reads 2 bytes → stream advances by 2
m_ObjectDescriptorId = (bits >> 6);
m_UrlFlag = ((bits & (1<<5)) != 0);

// (optional URL read if m_UrlFlag is set)

AP4_Position offset;
stream.Tell(offset);                 // offset = start + 2
AP4_SubStream* substream = new AP4_SubStream(
    stream, offset,
    payload_size - AP4_Size(offset - start)   // <-- underflow
);
```

Both `payload_size` and `AP4_Size(offset - start)` are `uint32_t`.
When `payload_size = 0` and `offset - start = 2`:

```
0 - 2 = 0xFFFFFFFE   (unsigned 32-bit wrap-around)
```

The result `0xFFFFFFFE` is widened to `AP4_LargeSize` (uint64_t) when
constructing the `AP4_SubStream`, giving `m_Size ≈ 4 GB`.

The while loop that follows then attempts to parse sub-descriptors from this
enormously oversized substream, reading far beyond the `iods` atom boundary.

## Trigger Path

```
mp42aac input.mp4
  → AP4_File::AP4_File(stream)
  → AP4_AtomFactory::CreateAtomFromStream            [Ap4AtomFactory.cpp]
  → AP4_IodsAtom::Create(size, stream)               [Ap4IodsAtom.cpp:44]
  → AP4_DescriptorFactory::CreateDescriptorFromStream [Ap4DescriptorFactory.cpp:84]
      tag = 0x01 (AP4_DESCRIPTOR_TAG_OD) or 0x11 (AP4_DESCRIPTOR_TAG_MP4_OD)
      payload_size = 0
  → AP4_ObjectDescriptor(stream, tag, header_size=2, payload_size=0)
      ReadUI16 → offset-start = 2
      0 - 2 = 0xFFFFFFFE ← UNDERFLOW
      AP4_SubStream(stream, offset, 0xFFFFFFFE)
      while (CreateDescriptorFromStream(*substream, ...) == AP4_SUCCESS) ...
```

## PoC File Structure

```
ftyp (20 bytes)
  brand=mp41, version=0, compat=mp41
moov (variable)
  mvhd (108 bytes, version=0, minimal valid header)
  iods
    version+flags: 0x00000000
    OD descriptor:
      tag  = 0x01  (AP4_DESCRIPTOR_TAG_OD)
      size = 0x00  (expandable encoding → payload_size = 0)
    [Extra bytes inside iods, beyond declared payload_size=0]:
      2 bytes: 0x00 0x00  ← consumed by ReadUI16 (OD_ID=0, URL_flag=false)
      5 bytes: 0xFF 0xFF 0xFF 0xFF 0x7F  ← sub-descriptor with payload_size=0x0FFFFFFF
```

The 2 extra bytes (`0x00 0x00`) are critical: without physical bytes for
`ReadUI16` to consume, the read fails, `bits` is set to 0, the stream does not
advance, `offset - start` remains 0, and no underflow occurs.

## Expected ASAN/UBSAN Behavior

### Primary signal
The integer underflow is **unsigned arithmetic** (`uint32_t - uint32_t`).
Standard `-fsanitize=undefined` does **not** flag unsigned integer overflow/underflow;
it is not undefined behavior in C++. Thus UBSAN produces no report for the
underflow itself.

ASAN does not track logical out-of-bounds file reads (reads via `fread` bypass
ASAN's shadow memory). Therefore, ASAN produces no report for reading past the
`iods` atom boundary.

### Secondary signal (OOM)
The crafted sub-descriptor (5 bytes: `0xFF 0xFF 0xFF 0xFF 0x7F`) encodes
`payload_size = 0x0FFFFFFF` (268 MB). `AP4_UnknownDescriptor` calls:

```cpp
m_Data.SetDataSize(0x0FFFFFFF);          // new AP4_Byte[268MB]
stream.Read(m_Data.UseData(), 0x0FFFFFFF); // reads 0 bytes (file at EOF)
```

On systems with virtual memory overcommit (typical Linux default), `new[]` for
268 MB succeeds without consuming physical RAM (no pages are accessed because
the subsequent read returns 0 bytes). The allocation is freed when the descriptor
is destroyed.

On **memory-constrained** systems or when `ASAN_OPTIONS=max_heap=...` limits
allocator size, `new[]` may throw `std::bad_alloc`, crashing the process.

### Verdict
**UNVERIFIED** on systems with virtual memory overcommit (no ASAN/UBSAN signal,
process exits cleanly with "ERROR: no audio track found").

The integer underflow is logically present and can be confirmed by inspection
of `Ap4ObjectDescriptor.cpp` lines 94–96. A crash would manifest when:
  - The environment has limited available memory, OR
  - The input file contains a large amount of valid-looking descriptor data
    beyond the `iods` atom, causing the SubStream loop to iterate many times
    and exhaust heap memory through accumulated descriptor allocations.

## Variants Tested

| Variant | OD tag | payload_size | Underflow result |
|---------|--------|--------------|------------------|
| 1       | 0x01   | 0            | 0 - 2 = 0xFFFFFFFE |
| 2       | 0x01   | 1            | 1 - 2 = 0xFFFFFFFF |
| 3       | 0x11   | 0            | 0 - 2 = 0xFFFFFFFE |
