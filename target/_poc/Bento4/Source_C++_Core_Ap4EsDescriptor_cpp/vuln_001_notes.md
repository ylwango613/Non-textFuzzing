# VULN 001 – Integer Underflow in EsDescriptor SubStream Size

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4EsDescriptor.cpp`, lines 100-110  
**CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)

### Root Cause

At line 103, Bento4 computes the remaining sub-descriptor payload as:

```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size-AP4_Size(offset-start));
```

Both `payload_size` and `AP4_Size(offset-start)` are `AP4_Size` = `AP4_UI32` (unsigned 32-bit). If more bytes were consumed than `payload_size` declares, the subtraction wraps to ~0xFFFFFFFE (~4 GB). The `while` loop at lines 105–109 then reads sub-descriptors from this artificially huge substream, going far beyond the declared ES descriptor boundary.

### Trigger Condition

- ES_Descriptor expandable-size = 3 (declares 3-byte payload)
- Flags byte = `0x20` (bit 5 set: `(0x20>>5)&7 = 1 = AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY`)
- Parser reads: ES_ID (2B) + flags (1B) = 3B (matches declared payload), THEN also reads DependsOn_ES_ID (2B) because STREAM_DEPENDENCY flag is set
- Total consumed = 5 bytes; `AP4_Size(5) – AP4_UI32(3)` wraps to `0xFFFFFFFE`

**Critical note on flags byte**: Bento4's `AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY = 1`
corresponds to bit 5 of the raw byte (`(bits>>5)&7 == 1`), which is `0x20`. This is
different from the MPEG-4 standard where streamDependenceFlag is bit 7 (`0x80`). Using
`0x80` sets m_Flags = 4 (OCR_STREAM), which does NOT trigger the dependency read.

## PoC Approach

The generator (`vuln_001_gen.py`) builds a minimal but structurally plausible MP4 file with:
- A proper `ftyp` + `moov` (mvhd + trak) + `mdat` layout
- A valid audio track hierarchy (tkhd → mdia → minf → stbl → stsd → mp4a → esds)
- Inside the `esds` box: a crafted ES_Descriptor with the minimal underflow trigger, followed
  by additional descriptor-like bytes that the overflow loop will attempt to parse as
  sub-descriptors beyond the ES descriptor's declared scope

## Expected Behaviour

1. `mp42aac` opens the file and calls `new AP4_File(*input)`
2. The atom factory parses the moov → trak → ... → esds hierarchy
3. `AP4_EsdsAtom::Create` → `AP4_DescriptorFactory::CreateDescriptorFromStream` → `AP4_EsDescriptor` constructor
4. The ES_Descriptor constructor hits the underflow at line 103, producing a SubStream of ~4 GB
5. The loop reads beyond the ES descriptor boundary into subsequent box data or EOF
6. Execution eventually terminates when the file's EOF is reached

## ASAN/UBSAN Detection

The primary underflow (`AP4_UI32` unsigned wrap) is **not** caught by `-fsanitize=undefined`
because unsigned integer overflow is defined behavior in C++ and is excluded from the
default `undefined` sanitizer group (it requires the additional
`-fsanitize=unsigned-integer-overflow` flag, which is not in the build).

The OOB reads occur through file I/O (`fread`) against the underlying `AP4_FileByteStream`,
not through a heap-allocated buffer visible to ASAN. As a result, ASAN also does not fire.

The vulnerability is observable through:
- Abnormal parsing duration (loop reads far more data than the declared descriptor scope)
- An information disclosure risk: if the caller's stream is a shared memory region or contains
  sensitive data beyond the esds boundary, the loop may expose that data to the parser

Status is set to UNVERIFIED because neither ASAN nor UBSAN produces an error report with
the current build configuration. The vulnerability is nevertheless confirmed by code analysis.
