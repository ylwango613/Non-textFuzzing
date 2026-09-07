# VULN-001: Integer Underflow in AP4_DecoderConfigDescriptor Stream Constructor

## Summary

An integer underflow in `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)` at line 92 of `Ap4DecoderConfigDescriptor.cpp` allows an attacker-controlled `esds` box to create an ~4 GB sub-stream, causing the descriptor parsing while loop to read adjacent MP4 box data as if it were DecoderConfig sub-descriptors (logical out-of-bounds read).

## Affected Binary

- `mp42aac` (Bento4)
- Trigger command: `mp42aac vuln_001.mp4 output.aac`

## Vulnerable Code

```cpp
// Ap4DecoderConfigDescriptor.cpp, line 92
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```

`payload_size` is `AP4_Size` = `AP4_UI32` (unsigned 32-bit). When the declared DecoderConfig descriptor payload size is less than 13 (e.g., 5), the subtraction wraps:

```
5 - 13 = 0xFFFFFFF3  (4294967283 bytes ~= 4 GB)
```

This inflated size is passed to `AP4_SubStream`, which stores it as `AP4_LargeSize` (64-bit) = `0x00000000FFFFFFF3`. The subsequent while loop calling `AP4_DescriptorFactory::CreateDescriptorFromStream()` reads bytes far beyond the `esds` box boundary, treating arbitrary MP4 box data as MPEG-4 descriptor bytes.

## Trigger Path

```
mp42aac input.mp4 output.aac
  -> AP4_File::AP4_File()
  -> AP4_AtomFactory: parse moov/trak/mdia/minf/stbl/stsd/mp4a/esds
  -> AP4_EsdsAtom::AP4_EsdsAtom(stream, ...)
  -> AP4_DescriptorFactory::CreateDescriptorFromStream(stream, ...) on tag 0x04
  -> new AP4_DecoderConfigDescriptor(stream, header_size=2, payload_size=5)
  -> line 92: payload_size(5) - 13 = 0xFFFFFFF3 --> ~4 GB AP4_SubStream
  -> while loop reads stts/stsc/stsz/stco box data as MPEG-4 descriptors (OOB)
```

## PoC Design

The `vuln_001.mp4` file places the DecoderConfigDescriptor **directly** in the `esds` box body (without the standard ES_Descriptor wrapper). This ensures the malicious stream passed to `AP4_DecoderConfigDescriptor` is the raw file stream rather than a 10-byte bounded ES_Descriptor SubStream.

### esds box structure (malicious)

```
esds {
  version/flags: 0x00000000
  DecoderConfigDescriptor (tag=0x04, encoded_size=5) {   <-- DIRECTLY in esds, size < 13
    payload: 5 bytes [0x40, 0x15, 0x00, 0x00, 0x00]
  }
  SLConfigDescriptor (tag=0x06, size=1) {
    0x02
  }
}
```

### Underflow Mechanics

1. `AP4_EsdsAtom` calls `CreateDescriptorFromStream` with raw file stream
2. Factory reads tag=0x04, encoded_size=5, calls `new AP4_DecoderConfigDescriptor(file_stream, 2, 5)`
3. Constructor records `start` (file pos), reads 13 bytes (5 payload + 8 adjacent bytes from SLConfig/stts)
4. Line 92: `new AP4_SubStream(file_stream, start+13, 5-13)` = SubStream with size=0xFFFFFFF3
5. While loop reads from file pos `start+13` through EOF, parsing stts/stsc/stsz/stco data as MPEG-4 descriptors

## Runtime Behavior

- **With standard ES_Descriptor wrapping**: The ES_Descriptor SubStream (m_Size=10) causes `esDescSubstream.Seek(15)` to fail immediately, so the OOB SubStream is created but cannot read anything.
- **With direct DecoderConfig in esds (this PoC)**: The ~4 GB SubStream wraps the raw file stream. The while loop reads until file EOF (about 60-80 bytes of adjacent box data), then exits cleanly.
- **No ASAN crash**: All reads go through `fread()` which gracefully returns EOS at EOF. ASAN does not instrument file I/O operations, so no heap-buffer-overflow is reported.

## Severity

The vulnerability constitutes a **logical out-of-bounds read** - bytes from adjacent MP4 boxes (stts, stsc, etc.) are parsed as MPEG-4 descriptors. An attacker could exploit this to:
- Cause unexpected descriptor objects to be created from arbitrary file data
- Potentially trigger further issues if crafted bytes at the right file offset match descriptor tags with large payload sizes, causing large heap allocations

A sanitizer-detected crash would require the file data to reside in a heap buffer with ASAN red zones (e.g., via AP4_MemoryByteStream), or if the adjacent bytes happen to encode a descriptor with a very large payload size, causing `AP4_UnknownDescriptor`/`AP4_DecoderSpecificInfoDescriptor` to allocate large buffers.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.mp4` with malicious DecoderConfig descriptor |
| `vuln_001_run.sh` | Runs gen.py then invokes mp42aac with ASAN/UBSAN |
| `vuln_001.mp4` | Generated malicious input file (527 bytes) |
| `vuln_001_out.aac` | Binary output (if created) |
| `vuln_001_run.log` | Full run output |
| `vuln_001_status.txt` | UNVERIFIED - underflow confirmed, no ASAN crash |
