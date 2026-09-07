# VULN 002 PoC Notes — Integer Underflow in AP4_DecoderConfigDescriptor

## Vulnerability Summary

- **Location**: `Bento4/Source/C++/Core/Ap4DecoderConfigDescriptor.cpp`, line 92
- **CWE-191** (Integer Underflow) → **CWE-125** (Out-of-Bounds Read)
- **Tool affected**: `mp42aac` (and any Bento4 consumer that parses esds atoms)

## Root Cause

```cpp
// Ap4DecoderConfigDescriptor.cpp line 92
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```

`payload_size` and `13` are both of type `AP4_Size` (= `uint32_t`). When `payload_size < 13`
(e.g., `payload_size = 5`), the subtraction underflows:

```
5 - 13 = 0xFFFFFFF8   (as uint32_t → 4,294,967,288)
```

The resulting `AP4_SubStream` is constructed with a declared size of ~4 GB. The factory loop
inside the DC constructor then iterates over this phantom 4 GB SubStream.

## Trigger Conditions

1. A valid MP4 with an audio track (hdlr handler_type = 'soun')
2. The mp4a sample description entry must contain an `esds` box
3. Inside the esds, embed an ES_Descriptor (tag 0x03) containing a DecoderConfig
   descriptor (tag 0x04) whose declared payload_size is < 13 (we use **5**)
4. The ES_Descriptor's own payload_size must be large enough for the factory to
   reach and parse the DC descriptor

## Generated File Structure

```
ftyp (20 bytes)
moov (521 bytes)
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr  (handler='soun')
      minf
        smhd
        dinf / dref (url , self-contained)
        stbl
          stsd
            mp4a (AudioSampleEntry)
              esds
                ES_Descriptor  (tag=0x03, payload_size=30)
                  ES_ID=1  flags=0x00
                  DecoderConfig (tag=0x04, DECLARED payload_size=5)  ← trigger
                    payload[0..4]:  0x40 0x15 0x00 0x00 0x00
                    [extra 8 bytes: allow DC constructor to read 13 bytes]
                    [bait 12 bytes: 0x05 0xFF 0xFF 0xFF 0x7F + zeros
                     → DecoderSpecificInfo header with size=0x0FFFFFFF]
mdat (8 bytes, empty)
```

## Exact Underflow Path

```
mp42aac
  → AP4_EsdsAtom::Create(...)
      → AP4_DescriptorFactory::CreateDescriptorFromStream(file_stream, ...)
          → AP4_EsDescriptor(file_stream, 2, 30)          // ES_Descriptor
              → AP4_SubStream(file_stream, offset, 27)    // ES SubStream (27 bytes)
              → AP4_DescriptorFactory loop on ES SubStream
                  → reads tag=0x04, payload_size=5
                  → AP4_DecoderConfigDescriptor(es_substream, 2, 5)
                      stream.Tell(start)                 // start = 2 in ES SubStream
                      stream.ReadUI08(...)               // reads 13 bytes total
                      ...
                      new AP4_SubStream(es_substream, 2+13, 5-13)
                                                         // size = 0xFFFFFFF8 ← UNDERFLOW
```

## Runtime Behavior (ASAN binary)

The tool reaches esds parsing and processes the malicious descriptor. The output
`"Audio Track: duration: 0 ms, sample count: 0"` confirms the code path was entered.

**No ASAN crash is produced.** Analysis of `AP4_SubStream::ReadPartial`:

```cpp
if (m_Position+bytes_to_read > m_Size) {
    bytes_to_read = (AP4_Size)(m_Size - m_Position);
}
```

And `AP4_SubStream::Seek`:
```cpp
if (position > m_Size) return AP4_FAILURE;
```

The DC SubStream (m_Offset=15, m_Size=0xFFFFFFF8) uses the ES SubStream as its container.
When the DC SubStream tries to seek its container to position 15+0 = 15, the ES SubStream
checks: `15 > 27`? No → seek succeeds. This allows the first 12 bytes (ES positions 15–26)
to be read via the 4 GB SubStream. When the DC SubStream tries to access ES position 27,
the ES SubStream's ReadPartial clamps the read to 0 bytes and returns EOS. The factory loop
exits cleanly.

**The bait bytes** (`0x05 0xFF 0xFF 0xFF 0x7F`) in the DC SubStream's window cause the
factory to create an `AP4_DecoderSpecificInfoDescriptor` with `payload_size = 0x0FFFFFFF`
(268,435,455 bytes = ~256 MB). This triggers a 256 MB heap allocation, which succeeds on
most systems. Only 7 bytes of file data are read into the buffer; the rest is uninitialized.
ASAN does not flag this because the read stays within the allocated 256 MB region.

## Why the Underflow is Still Dangerous

Even though ASAN does not crash in this test, the vulnerability is real:

1. **Different stream implementations**: If a caller passes a file stream without wrapping
   it in a SubStream, the DC SubStream with size 0xFFFFFFF8 directly overlays the full
   remaining file. The factory loop can then read arbitrary bytes from the file far past the
   esds box boundary — a genuine OOB read (CWE-125).

2. **Large allocation**: In the current test, the bait bytes cause a 256 MB allocation.
   Under memory pressure, `new AP4_Byte[0x0FFFFFFF]` throws `std::bad_alloc`, which
   propagates as an uncaught exception and crashes the process (DoS).

3. **Arithmetic on the malformed size**: Code that adds or multiplies the SubStream's
   reported size (0xFFFFFFF8) with other values is likely to overflow further, creating
   additional exploitable conditions.

## Files

| File | Purpose |
|------|---------|
| `vuln_002_gen.py`  | Generates `vuln_002.mp4` |
| `vuln_002_run.sh`  | Runs gen.py + mp42aac with ASAN |
| `vuln_002.mp4`     | Malicious MP4 (549 bytes) |
| `vuln_002_result.txt` | mp42aac stdout/stderr output |
| `vuln_002_notes.md`   | This file |
| `vuln_002_status.txt` | One-line verification status |
