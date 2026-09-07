# VULN 001 - Integer Underflow in AP4_DecoderConfigDescriptor

## Affected File
`Source/C++/Core/Ap4DecoderConfigDescriptor.cpp`, line 92

## Vulnerability Description

`AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(stream, header_size, payload_size)`
unconditionally reads 13 bytes from the stream (1B OTI + 1B bits + 3B BufferSize + 4B MaxBitrate + 4B AvgBitrate), then at line 92 computes:

```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```

Both `payload_size` and `13` are `AP4_Size` (uint32). If `payload_size < 13`, the subtraction underflows to a large positive value (e.g., `4 - 13 = 0xFFFFFFF3 ≈ 4 billion`). This value is zero-extended to `AP4_LargeSize` (uint64) when passed to `AP4_SubStream`.

The `AP4_SubStream` boundary checks compare `m_Position + bytes_to_read > m_Size`, but `m_Size = 0xFFFFFFF3` makes this check trivially false for all reasonable reads. As a result, the substream reads proceed far beyond the declared end of the DecoderConfig descriptor, constituting an **out-of-bounds read**.

## Trigger Conditions

- An `esds` box exists inside an `mp4a` sample entry
- The ES_Descriptor (tag=0x03) contains a DecoderConfig descriptor (tag=0x04)
- The DecoderConfig's encoded `payload_size` is less than 13 (e.g., 4)

## Exploitation Path

```
mp42aac
  -> AP4_File(stream)          # parses all atoms
  -> AP4_EsdsAtom::Create()    # reads esds box
  -> AP4_DescriptorFactory::CreateDescriptorFromStream()  # reads ES_Descriptor
  -> AP4_EsDescriptor()        # reads ES_ID, flags, creates ES SubStream
  -> AP4_DescriptorFactory::CreateDescriptorFromStream()  # reads DecoderConfig (tag=0x04)
  -> AP4_DecoderConfigDescriptor(stream, 2, 4)  # payload_size = 4 < 13
     line 92: new AP4_SubStream(stream, start+13, 4-13)
             = new AP4_SubStream(stream, start+13, 0xFFFFFFF3)  # UNDERFLOW
  -> AP4_DescriptorFactory::CreateDescriptorFromStream(*substream)
     reads tag=0x05 and size=64 from OOB memory
  -> AP4_DecoderSpecificInfoDescriptor(substream, 2, 64)
     m_Info.SetDataSize(64)    # heap allocation of 64 bytes
     stream.Read(data, 64)     # 64 bytes OOB read
```

## PoC File Layout

The crafted `vuln_001.mp4` places a fake `DecoderSpecificInfo` descriptor
(tag=0x05, payload_size=64) at ES SubStream offset 15 — exactly where the
underflowed SubStream begins reading. This forces a 64-byte OOB heap read.

### ES SubStream Content (positions 0–80):
| Offset | Value  | Description |
|--------|--------|-------------|
| 0      | 0x04   | DecoderConfig tag |
| 1      | 0x04   | DecoderConfig size = 4 (UNDERFLOW trigger) |
| 2      | 0x40   | OTI = 0x40 (MPEG-4 Audio) — DC payload start (`start=2`) |
| 3      | 0x15   | bits: stream_type=5 (audio), upstream=0 |
| 4–5    | 0x00   | Declared DC payload ends here (4 bytes total) |
| 6–14   | 0x00×9 | DC reads 9 more bytes beyond declared payload |
| 15     | 0x05   | **Fake DSI tag** (read by DC SubStream at `start+13`) |
| 16     | 0x40   | Fake DSI size = 64 |
| 17–80  | 0x00×64| Fake DSI payload (64-byte OOB read) |

## Expected ASAN/UBSAN Output

With ASAN instrumentation, expect:

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 64 at 0x...
SUMMARY: AddressSanitizer: heap-buffer-overflow
```

or with UBSAN:

```
runtime error: unsigned integer overflow: 4 - 13 cannot be represented in type 'unsigned int'
```

Without sanitizers, the binary may:
- Crash with SIGSEGV if the OOB read crosses a page boundary
- Exit normally after reading garbage data from adjacent memory
- Exhibit undefined behavior with no visible crash

## Impact

- **Confidentiality**: OOB heap read — may leak adjacent heap contents
- **Availability**: With large fake payload_size values, triggers OOM (DoS)
- **Severity**: Medium–High (OOB read, potential heap info disclosure)

## Mitigation

Add a bounds check before computing the SubStream size:
```cpp
if (payload_size < 13) {
    // error: malformed descriptor
    substream->Release();
    return;
}
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```
