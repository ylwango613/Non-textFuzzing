# VULN 004 - PoC Notes

## Vulnerability

**Title**: AP4_DecoderConfigDescriptor hardcoded-constant subtraction integer underflow → OOB read  
**File**: `Source/C++/Core/Ap4DecoderConfigDescriptor.cpp`, line 92  
**CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)

## Root Cause

```cpp
// Ap4DecoderConfigDescriptor.cpp line 92
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```

`payload_size` is `AP4_Size` (uint32). When `payload_size < 13`, the subtraction wraps:
- `payload_size=12`: `12 - 13 = 0xFFFFFFFF` → 4,294,967,295 byte SubStream
- `payload_size=0`:  `0  - 13 = 0xFFFFFFF3` → 4,294,967,283 byte SubStream

The constructor always reads 13 bytes first (OTI:1 + bits:1 + bufferSize:3 + maxBR:4 + avgBR:4).
When `payload_size < 13`, some of those 13 bytes are read from OUTSIDE the declared descriptor
payload. Then the giant SubStream allows the descriptor factory loop to parse bytes far beyond
the descriptor boundary.

## Trigger Path

```
mp42aac <file> /dev/null
  -> AP4_File -> AP4_Movie -> AP4_Track
  -> AP4_SampleDescription -> AP4_EsdsAtom (stsd/mp4a/esds)
  -> AP4_DescriptorFactory::CreateDescriptorFromStream
  -> AP4_EsDescriptor (tag=0x03)
     -> ES SubStream (payload_size - 3 bytes)
     -> AP4_DescriptorFactory::CreateDescriptorFromStream (sub-loop)
     -> AP4_DecoderConfigDescriptor (tag=0x04, payload_size=12)  ← VULNERABLE
        Line 92: new AP4_SubStream(es_substream, start+13, 12-13=0xFFFFFFFF)
```

## PoC Design

Three crafted mp4a sample entries, each with a different esds configuration:

### Variant A (primary): ES payload=19, DC payload=12
- ES_Descriptor: tag=0x03, size=19
  - ES SubStream size = 19 - 3 = 16 bytes (large enough for offset-15 seek)
  - DC_Descriptor: tag=0x04, **size=0x0C (12)** ← triggers 12-13=0xFFFFFFFF underflow
  - 2 extra bytes at ES SubStream positions 14-15 for DC SubStream reads
- DC constructor reads 13 bytes (positions 2-14 in ES SubStream, all valid)
- DC SubStream created at ES SubStream offset=15, size=0xFFFFFFFF
- DC SubStream.Seek(15): 15 ≤ 16 → succeeds
- DC SubStream reads 1 byte at ES SubStream pos 15 → successfully reads beyond DC payload

### Variant B: ES payload=20, DC payload=0
- DC payload_size=0: underflow is `0-13=0xFFFFFFF3` (even larger)
- DC constructor reads 13 bytes from "padding" bytes in ES payload
- DC SubStream = (es_substream, offset=15, size=0xFFFFFFF3)

### Variant C: DC directly in esds (no ES wrapper)
- DC_Descriptor (tag=0x04, size=12) placed directly in esds atom
- DC constructor's `stream` parameter is the RAW file stream (no size limit)
- DC SubStream = (file_stream, start+13, 0xFFFFFFFF) → no SubStream boundary guard
- The loop reads actual file bytes from position start+13 onwards

## Actual Run Results (VERIFIED_CRASH)

ASAN (LeakSanitizer) detected **265 bytes leaked in 6 allocations** when running against
`vuln_004.mp4`. Stack traces confirm the vulnerability trigger:

1. **Direct leak of 72 bytes** from `AP4_DescriptorFactory::CreateDescriptorFromStream`
   called from `AP4_EsdsAtom::Create` — the ES_Descriptor or DC descriptor itself leaks.

2. **Indirect leak of 88+56 bytes** from `AP4_DescriptorFactory::CreateDescriptorFromStream`
   called inside `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor` — the DC
   constructor's SubStream loop creates descriptors from OOB file bytes.

3. **Indirect leak of 48 bytes** from the DC constructor's internal SubStream (the 0xFFFFFFFF-
   sized SubStream) allocating sub-descriptor objects.

4. **Indirect leak of 1 byte** from `AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor`
   called from inside `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor` — the DC
   SubStream read bytes from OUTSIDE the DC payload, those bytes had tag=0x02 (IOD), and
   Bento4 actually constructed an `AP4_InitialObjectDescriptor`! This confirms that the
   DC SubStream successfully read and interpreted file bytes beyond the DC boundary.

### Significance

The call chain:
```
AP4_DecoderConfigDescriptor::ctor
  -> AP4_DescriptorFactory::CreateDescriptorFromStream (*substream with size=0xFFFFFFFF*)
     -> AP4_InitialObjectDescriptor::ctor   ← OOB bytes parsed as IOD!
        -> AP4_String::operator=             ← allocates 1 byte (leaked)
```

This proves the `0xFFFFFFFF`-sized SubStream successfully read file bytes beyond the
declared DC descriptor boundary, the parser treated those bytes as a valid IOD descriptor
(tag=0x02), fully constructed it, and that object leaked because the parent DC descriptor
never properly accounts for it in the cleanup chain.

## Files

| File | Description |
|------|-------------|
| `vuln_004_gen.py` | Python script to generate `vuln_004.mp4` |
| `vuln_004.mp4` | Crafted MP4 with 3 variant esds descriptors |
| `vuln_004_run.sh` | Shell script to run mp42aac and collect results |
| `vuln_004_result.txt` | stdout/stderr from the binary run |
| `asan.log.*` | ASAN/UBSAN output (if any) |
| `vuln_004_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR |
| `vuln_004_notes.md` | This file |

## Mitigation

Add a bounds check before the SubStream creation in `Ap4DecoderConfigDescriptor.cpp`:

```cpp
if (payload_size < 13) {
    // payload too small: skip sub-descriptor parsing
    return;
}
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```
