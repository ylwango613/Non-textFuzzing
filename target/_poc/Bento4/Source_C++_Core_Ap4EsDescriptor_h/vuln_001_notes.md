# VULN 001 – AP4_EsDescriptor Integer Underflow → Out-of-Bounds Read

## Vulnerability Summary

| Field        | Value |
|-------------|-------|
| File        | `Bento4/Source/C++/Core/Ap4EsDescriptor.cpp` lines 100–103 |
| Function    | `AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)` |
| CWE         | CWE-191 (Integer Underflow) → CWE-125 (Out-of-Bounds Read) |
| Binary      | `mp42aac` |
| Trigger     | ES_Descriptor with `payload_size=3` and `flags_byte=0x20` |

---

## Root Cause

The constructor reads fixed fields from the stream and then computes the
remaining size for sub-descriptors:

```cpp
AP4_Position start;
stream.Tell(start);

stream.ReadUI16(m_EsId);   // 2 bytes
stream.ReadUI08(bits);     // 1 byte
m_Flags = (bits >> 5) & 7;

if (m_Flags & AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY) {  // flag = 1
    stream.ReadUI16(m_DependsOn);  // 2 MORE bytes → total 5 bytes consumed
}

AP4_Position offset;
stream.Tell(offset);
// LINE 102-103 — integer underflow:
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                               payload_size - AP4_Size(offset - start));
//  ^^ payload_size=3, AP4_Size(offset-start)=5
//  ^^ unsigned subtraction: 3 - 5 = 0xFFFFFFFE  (~4 GB SubStream!)
```

### Flag bit decoding

`AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY = 1` (from `Ap4EsDescriptor.h:52`).

The flag is stored in bits[7:5] of the flags byte:
```
m_Flags = (bits >> 5) & 7
```
So `m_Flags & 1` is set when bit 5 of the byte is set, i.e., `bits = 0x20`.

---

## Trigger Conditions

Craft an ES_Descriptor where:
- `payload_size = 3` (covers es_id[2] + flags_byte[1] exactly)
- `flags_byte = 0x20` → `m_Flags = 1` → `streamDependenceFlag` set

The code then reads `DependsOn_ES_Id` (2 bytes) from beyond the declared
3-byte payload — an **out-of-bounds read** of file data.

The subsequent `payload_size - 5 = 0xFFFFFFFE` creates a ~4 GB SubStream,
allowing the parser to consume arbitrary file data after the ES_Descriptor
as if it were nested sub-descriptors.

---

## PoC MP4 Structure

```
ftyp  [brand: isom]
moov
  mvhd
  trak
    tkhd  [track_id=1, audio]
    mdia
      mdhd  [timescale=44100]
      hdlr  [handler=soun]
      minf
        smhd
        dinf → dref → url  [self-contained]
        stbl
          stsd
            mp4a  [ch=2, bits=16, rate=44100]
              esds  ← MALICIOUS
                version+flags: 00 00 00 00
                ES_Descriptor:
                  tag  = 0x03
                  size = 0x03          ← payload_size=3
                  [payload byte 0] es_id_hi = 0x00
                  [payload byte 1] es_id_lo = 0x01
                  [payload byte 2] flags    = 0x20  ← streamDependenceFlag
                  [OOB byte 3] DependsOn_hi = 0x00
                  [OOB byte 4] DependsOn_lo = 0x02
                  [SubStream data — parsed beyond declared boundary]
                  DecoderConfigDescriptor (tag=0x04, payload=13)
                  SLConfigDescriptor      (tag=0x06, payload=1)
          stts  [0 entries]
          stsc  [0 entries]
          stsz  [0 samples]
          stco  [0 entries]
mdat  [empty]
```

---

## Observed Effects

1. **OOB read #1**: `stream.ReadUI16(m_DependsOn)` reads 2 bytes beyond
   the 3-byte declared payload boundary.

2. **Huge SubStream**: `payload_size - 5 = 0xFFFFFFFE` is passed as the
   SubStream size. The parser is now allowed to read ~4 GB of data past
   the declared boundary.

3. **Sub-descriptor parsing beyond boundary**: Any bytes following the
   ES_Descriptor payload in the file (here: a crafted DecoderConfig +
   SLConfig) are parsed as ES_Descriptor sub-descriptors, even though they
   are logically outside the declared payload.

4. **ASAN note**: Because reads go through the OS file I/O layer
   (`AP4_FileByteStream`), ASAN does not flag the out-of-bounds reads as
   heap-buffer-overflows. The vulnerability is a logical boundary violation
   (information disclosure / unintended parsing of adjacent data). A memory
   safety crash would require a deeper allocation from a crafted
   sub-descriptor — see further exploitation paths below.

---

## Further Exploitation Paths

- **Heap allocation with corrupt size**: Place a `DecoderSpecificInfo`
  (tag=0x05) after the DependsOn bytes with a large varint-encoded
  `payload_size`. The constructor calls `m_Info.SetDataSize(payload_size)`
  and then `stream.Read(m_Info.UseData(), payload_size)`. If `payload_size`
  encodes a value near `UINT32_MAX`, a huge heap allocation is attempted,
  potentially causing `std::bad_alloc` or an allocation failure crash.

- **Nested underflow chain**: Place a `DecoderConfigDescriptor`
  (tag=0x04) with `payload_size < 13` after the DependsOn bytes. The
  DecoderConfig constructor at line 92 (`payload_size - 13`) suffers a
  second underflow, creating another enormous SubStream. This amplifies
  the OOB read surface.

- **Information disclosure**: If the bytes after the ES_Descriptor payload
  are part of another atom (e.g., `stts`, `mvhd`), those atoms' raw data
  are parsed as sub-descriptors, leaking structural information from
  adjacent containers.

---

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Python script generating the malicious `vuln_001.mp4` |
| `vuln_001_run.sh` | Shell wrapper: runs gen.py → runs mp42aac → checks for sanitizer output |
| `vuln_001.mp4`    | Generated malicious MP4 file |
| `vuln_001_run.log`| Raw output from the binary run |
| `vuln_001_status.txt` | Machine-readable run result |
| `vuln_001_notes.md` | This file |
