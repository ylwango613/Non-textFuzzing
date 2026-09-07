# VULN 003: Wrong fields_size Accounting in AP4_IpmpDescriptor — 16-Byte OOB Read

**CWE**: CWE-125 (Out-of-bounds Read)  
**Binary**: `mp42aac` (Bento4)  
**Source**: `Bento4/Source/C++/Core/Ap4Ipmp.cpp` — `AP4_IpmpDescriptor::AP4_IpmpDescriptor()`

---

## Vulnerable Code

```cpp
AP4_IpmpDescriptor::AP4_IpmpDescriptor(AP4_ByteStream& stream,
                                        AP4_Size        header_size,
                                        AP4_Size        payload_size) { ...
    stream.ReadUI08(m_DescriptorId);   // 1 byte consumed
    stream.ReadUI16(m_IpmpsType);      // 2 bytes consumed; total = 3

    if (m_DescriptorId == 0xFF && m_IpmpsType == 0xFFFF) {
        AP4_Size fields_size = 3+3;    // BUG: set to 6, intended to account for
                                       //      3 (initial) + 2 (DescriptorIdEx) + 1 (CPC)
                                       //      but FORGETS the 16 bytes of m_ToolId

        stream.ReadUI16(m_DescriptorIdEx);      // 2 bytes consumed; total = 5
        stream.Read(m_ToolId, 16);              // 16 bytes consumed; total = 21
        stream.ReadUI08(m_ControlPointCode);    // 1 byte consumed; total = 22
        if (m_ControlPointCode > 0) {
            stream.ReadUI08(m_SequenceCode);    // (not taken when CPC==0)
            ++fields_size;
        }
        // fields_size is still 6 here; correctly should be 22 (or 23 if CPC>0)

        if (fields_size < payload_size) {       // 6 < 30 → true
            m_Data.SetDataSize(payload_size - fields_size);            // allocates 24 bytes
            stream.Read(m_Data.UseData(), payload_size - fields_size); // tries to read 24 bytes
            // Only 30-22=8 bytes remain in IPMP payload, so 16 bytes are read
            // from BEYOND the IPMP descriptor's declared payload boundary.
        }
    }
}
```

**Root cause**: `fields_size` is initialized to `3+3=6` intending to account for 3 (initial
reads) + 2 (`m_DescriptorIdEx`) + 1 (`m_ControlPointCode`) = 6 bytes. However, the 16 bytes
consumed by `stream.Read(m_ToolId, 16)` are never added to `fields_size`. The correct
value would be 3+2+16+1 = 22 (or 23 if `m_ControlPointCode > 0`).

---

## Trigger Conditions

| Field | Value | Purpose |
|---|---|---|
| IPMP descriptor tag | `0x0B` | Selects `AP4_IpmpDescriptor` factory path |
| `m_DescriptorId` | `0xFF` | Enters the vulnerable branch |
| `m_IpmpsType` | `0xFFFF` | Confirms the branch |
| `m_ControlPointCode` | `0x00` | Keeps `fields_size` at 6 (no `++fields_size`) |
| `payload_size` | `30` | Sufficient: `30 - 6 = 24` bytes allocated/read; `30 - 22 = 8` remain |

---

## PoC File Structure

```
ftyp
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr (soun)
      minf
        smhd
        dinf (dref/url)
        stbl
          stsd
            mp4a
              esds  ← version=0, flags=0
                ES_Descriptor (tag=0x03, payload=51B)
                  ES_ID=1, flags=0x00
                  IPMP_Descriptor (tag=0x0B, payload=30B)
                    m_DescriptorId=0xFF
                    m_IpmpsType=0xFFFF
                    m_DescriptorIdEx=0x0001
                    m_ToolId=0xAA×16
                    m_ControlPointCode=0x00
                    tail_data=0x00×8
                  [16 bytes 0xBB padding]  ← OOB bytes
          stts (0 entries)
          stsc (0 entries)
          stsz (0 entries)
          stco (0 entries)
```

**Key layout detail**: The ES_Descriptor payload is 51 bytes (not the minimal 35).
The extra 16 bytes (`0xBB × 16`) are appended after the IPMP descriptor within the
ES_Descriptor payload. This is critical:

- `AP4_EsDescriptor` creates a `SubStream` of size `51 - 3 = 48` bytes (after reading
  the 3-byte ES_ID+flags header).
- The SubStream contains: `[IPMP_tag(1)][IPMP_size(1)][IPMP_payload(30)][0xBB×16(16)] = 48B`
- The IPMP constructor consumes 22 bytes from the SubStream (position reaches 24), then
  tries to read 24 more bytes (`payload_size - fields_size = 30 - 6 = 24`).
- With 48 - 24 = 24 bytes available in the SubStream, all 24 bytes are read:
  - Bytes [24..31] = last 8 bytes of the legitimate IPMP payload
  - Bytes [32..47] = 16 × `0xBB` **outside the IPMP descriptor's declared scope** ← OOB

---

## Impact

- The IPMP descriptor reads 16 bytes from beyond its declared payload boundary.
- The extra bytes (here `0xBB×16`) are stored in `m_Data` as if they were IPMP data.
- Subsequent descriptors in the same ES_Descriptor are parsed from the wrong stream
  position (the factory seeks back to `offset+header_size+payload_size = 32`, skipping
  the padding, so the SubStream does advance correctly — but the data already absorbed
  into `m_Data` is wrong).
- In a real-world attack, this could:
  - Leak adjacent memory contents into parsed data structures.
  - Cause downstream processing to use attacker-controlled or corrupted data.
  - Lead to further memory corruption if the extra bytes influence control flow.

---

## Expected ASAN/UBSAN Output

With ASAN, the test may report:
- A heap-buffer-overflow if the OOB read extends past an allocator boundary, or
- Incorrect but non-crashing behavior (UNVERIFIED) if the reads fall within valid
  heap regions — the logical OOB is still present and exploitable.

With UBSAN, integer issues in size arithmetic could also be reported.
