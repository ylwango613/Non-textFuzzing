# VULN 001 — AP4_DecoderConfigDescriptor SubStream Integer Underflow

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4DecoderConfigDescriptor.cpp`, line 92  
**Function**: `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)`

```cpp
// line 80-99
stream.Tell(start);
stream.ReadUI08(m_ObjectTypeIndication);   //  1 byte
stream.ReadUI08(bits);                     //  1 byte
stream.ReadUI24(m_BufferSize);             //  3 bytes
stream.ReadUI32(m_MaxBitrate);             //  4 bytes
stream.ReadUI32(m_AverageBitrate);         //  4 bytes  (total: 13 bytes)

// BUG: unsigned underflow when payload_size < 13
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```

When `payload_size = 0`, the subtraction `0 - 13` for `AP4_Size` (unsigned int) wraps to
`0xFFFFFFF3` (~4.3 GB). The resulting SubStream carries an enormous virtual size.

## Trigger Path

```
mp42aac
  -> AP4_File
  -> AP4_MoovAtom
  -> AP4_IodsAtom
  -> AP4_DescriptorFactory::CreateDescriptorFromStream
  -> AP4_InitialObjectDescriptor (IOD, tag=0x10)
  -> AP4_EsDescriptor (tag=0x03)
  -> AP4_DecoderConfigDescriptor (tag=0x04, payload_size=0)
       *** underflow here ***
```

## PoC Construction (two variants)

### Variant A — double underflow (primary, in `vuln_001.mp4`)

The ES_Descriptor is given a **declared payload_size=2**, but its constructor always
reads 3 bytes (2 for ES_ID + 1 for flags) from the parent IOD child stream before
computing the remaining-bytes count:

```
new AP4_SubStream(stream, offset, es_payload_size - (offset-start))
                                  = 2 - 3 = 0xFFFFFFFF   <-- ES underflow
```

This makes the ES child SubStream's `m_Size = 0xFFFFFFFF`, so the DC descriptor
bytes appear valid to the factory, and DC constructor can read its 13 "fixed"
bytes from real file data before triggering its own underflow:

```
new AP4_SubStream(stream, start+13, 0 - 13) = (stream, start+13, 0xFFFFFFF3)
```

### Variant B — simple underflow

Standard descriptor chain: IOD → ES(correct size) → DC(payload_size=0).
The DC underflow still occurs but DC's child SubStream is bounded by the
(correctly sized) ES child SubStream.

## Why ASAN/UBSAN Does Not Fire

1. **Unsigned underflow is defined behaviour in C/C++** — `AP4_Size(0) - 13` wraps
   to `0xFFFFFFF3` without UB; `-fsanitize=unsigned-integer-overflow` is not
   included in the build's `-fsanitize=undefined` set.

2. **All reads go through layered SubStream bounds checks** — `AP4_SubStream::Seek`
   enforces `if (position > m_Size) return AP4_FAILURE`.  Even though the DC's child
   SubStream declares `m_Size = 0xFFFFFFF3`, its container (ES child SubStream, or the
   IOD child SubStream via Variant A) limits actual reads to the file's real byte range.
   File I/O returns `AP4_ERROR_EOS` at end-of-file without touching heap memory.

3. **No heap allocation is sized by the underflowed value** — the only allocation is
   `new AP4_SubStream(...)` which stores the huge size as a field but does not
   allocate a proportional heap buffer.  `AP4_UnknownDescriptor` only allocates
   what it reads (0 bytes from null-padded region).

## Observable Effect

- The DC constructor reads 13 bytes **past** the declared 0-byte payload boundary,
  consuming bytes that belong to adjacent ES descriptor padding.
- The DC's child SubStream silently covers a virtual ~4 GB window; in practice it
  exhausts the parent's actual byte range and the while-loop exits cleanly.
- The program outputs **"ERROR: no audio track found"** and exits with code 0.

## Files

| File | Role |
|------|------|
| `vuln_001_gen.py` | Generates `vuln_001.mp4` (Variant A, double-underflow) |
| `vuln_001.mp4` | Crafted 214-byte MP4 triggering the underflow code path |
| `vuln_001_run.sh` | Runs mp42aac under ASAN+UBSAN and collects output |
| `vuln_001_result.txt` | Actual binary output |
| `vuln_001_status.txt` | Verification result |

## Remediation

Add a guard before the SubStream creation:

```cpp
if (payload_size < 13) {
    // payload too small to contain mandatory fields; skip sub-descriptors
    substream->Release();
    return;
}
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```
