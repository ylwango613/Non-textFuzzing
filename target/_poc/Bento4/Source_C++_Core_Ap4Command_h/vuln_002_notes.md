# VULN 002 – AP4_InitialObjectDescriptor Substream Size Integer Underflow

## Vulnerability Summary

**CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)  
**File**: `Source/C++/Core/Ap4ObjectDescriptor.cpp`, lines 215-263  
**Function**: `AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor()`

## Root Cause

The constructor records `start` position, reads 2 bytes via `ReadUI16(bits)`, and
(when the URL flag is clear) reads 5 additional profile-level bytes, advancing
`offset - start` to 7.  The remaining substream size is computed as:

```cpp
AP4_Size substream_size = payload_size - AP4_Size(offset - start);
```

Both operands are unsigned 32-bit values.  When `payload_size = 1`:

```
1 - 7  →  0xFFFFFFFA   (unsigned wrap-around)
```

`AP4_SubStream` is then created with this ~4 GiB size, causing the subsequent
descriptor-reading loop to attempt reads far beyond the actual `iods` atom,
triggering an out-of-bounds read.

## PoC Approach

The crafted MP4 (`vuln_002.mp4`) contains:

```
ftyp  (24 bytes)
moov
  mvhd  (108 bytes, version=0, minimal valid header)
  iods
    version+flags = 0x00000000
    descriptor:
      tag  = 0x02  (InitialObjectDescriptor)
      size = 0x01  (expandable encoding, payload_size = 1)
      data = 0x00  (single payload byte)
```

The `iods` descriptor tag 0x02 routes through `AP4_DescriptorFactory` into
`AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor()`.  With
`payload_size = 1`, the constructor reads 7 bytes of header (2 for the bits
field + 5 for profile levels) against a 1-byte budget, causing the underflow.

## Expected Behavior

- ASAN should report a **heap-buffer-overflow** or **out-of-bounds read** error.
- UBSAN may report a **signed/unsigned integer overflow** or **invalid value**.
- The program may also segfault while iterating over the huge synthetic substream.

## Fallback Variants (if tag=0x02 does not trigger)

- Use `tag = 0x10` (alternative IOD tag accepted by `AP4_DescriptorFactory`)
- Vary `payload_size`: 0, 2, 3, 4, 5, 6 — all underflow when the header consumes 7 bytes
