# PoC Notes: Bento4 DecoderConfigDescriptor Integer Underflow

## Vulnerability Summary

- **CVE**: N/A (internally tracked)
- **CWE**: CWE-191 (Integer Underflow / Wrap-Around)
- **Binary**: `mp42aac` (Bento4)
- **Function**: `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream&, AP4_Size header_size, AP4_Size payload_size)` at `Source/C++/Core/Ap4DecoderConfigDescriptor.cpp:92`

## Root Cause

In the parsing constructor of `AP4_DecoderConfigDescriptor`, the `payload_size` (type `AP4_Size`, which is `uint32_t`) is subtracted from the constant 13 to compute the size of a sub-stream for child descriptors:

```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```

When `payload_size < 13`, the unsigned subtraction wraps around:
- `payload_size = 0` → `0 - 13 = 0xFFFFFFF3` (~4 GB)

This creates an `AP4_SubStream` with an erroneous size of ~4 GB, permitting reads far beyond the actual DecoderConfigDescriptor payload boundary.

## Trigger Condition

An `esds` atom must contain an `ES_Descriptor` (tag=0x03) that contains a `DecoderConfigDescriptor` (tag=0x04) whose declared size field is 0 (or any value less than 13).

## PoC File Structure

```
ftyp
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr  (soun)
      minf
        smhd
        dinf
          dref (url, self-contained)
        stbl
          stsd
            mp4a  <-- AudioSampleEntry
              esds  <-- full-box, version=0
                ES_Descriptor   tag=0x03  size=5
                  es_id=0x0001  flags=0x00
                  DecoderConfigDescriptor tag=0x04  size=0x00  ← TRIGGER
          stts (empty)
          stsc (empty)
          stsz (empty)
          stco (empty)
  mdat (empty)
```

## Expected Behavior

When `mp42aac` parses `vuln_001.mp4`:

1. `AP4_EsdsAtom::Create` reads the `esds` box and calls `CreateDescriptorFromStream`.
2. `CreateDescriptorFromStream` reads tag=0x03, size=5, instantiates `AP4_EsDescriptor(stream, 2, 5)`.
3. `AP4_EsDescriptor` reads `es_id` (2 bytes) and `flags` (1 byte), then creates a 2-byte SubStream covering the remaining ES payload (the DecoderConfig header bytes 0x04 0x00).
4. `CreateDescriptorFromStream` on that SubStream reads tag=0x04, size=0x00, calls `AP4_DecoderConfigDescriptor(substream, 2, 0)`.
5. **Inside the constructor**, `payload_size - 13 = 0 - 13 = 0xFFFFFFF3` (unsigned underflow).
6. `new AP4_SubStream(stream, start+13, 0xFFFFFFF3)` is allocated with a ~4 GB declared size.
7. Subsequent `CreateDescriptorFromStream` calls on this huge SubStream attempt seeks/reads that are blocked by the parent SubStream's bounds check (size=2), so reads fail gracefully and the loop exits.

## ASAN / UBSAN Output

- If the binary is compiled with `-fsanitize=unsigned-integer-overflow`, UBSAN will report unsigned integer overflow at the `payload_size - 13` expression.
- Without that specific flag, the underflow is silent in the current build but the erroneous SubStream is created.
- The PoC reliably reaches the vulnerable code path; the observable crash depends on sanitizer flags in use.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.mp4` (540 bytes) |
| `vuln_001_run.sh` | Runs `mp42aac` with ASAN options, collects output |
| `vuln_001.mp4` | Generated malicious MP4 (created by `vuln_001_gen.py`) |
| `vuln_001_result.txt` | stdout/stderr + ASAN log from the run |
| `vuln_001_status.txt` | Single-line verdict (`VERIFIED_CRASH` / `UNVERIFIED`) |
