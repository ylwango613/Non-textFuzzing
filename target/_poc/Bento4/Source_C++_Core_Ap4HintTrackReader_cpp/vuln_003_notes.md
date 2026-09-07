# VULN-003: Integer Underflow Leading to Heap Corruption
## AP4_RtpSampleData Constructor (Ap4RtpHint.cpp)

### Vulnerability Location
- **File**: `Source/C++/Core/Ap4RtpHint.cpp`
- **Function**: `AP4_RtpSampleData::AP4_RtpSampleData(AP4_ByteStream& stream, AP4_UI32 size)`
- **Line**: 70 `AP4_Size extra_data_size = size - (AP4_UI32)(extra_data_start-start);`
- **CWE**: CWE-191 (Integer Underflow) → CWE-122 (Heap-based Buffer Overflow)

### Call Chain (intended trigger)
```
mp42aac main()
  └─ AP4_HintTrackReader::GetRtpSample(index)         [Ap4HintTrackReader.cpp:133]
       └─ new AP4_RtpSampleData(rtp_data_stream,       [Ap4HintTrackReader.cpp:143]
                                m_CurrentHintSample.GetSize())
            └─ size = stsz sample_size (attacker-controlled)
               extra_data_size = size - (extra_data_start - start)  ← UNDERFLOW
```

### Root Cause

```cpp
// Ap4RtpHint.cpp:50-75
AP4_RtpSampleData::AP4_RtpSampleData(AP4_ByteStream& stream, AP4_UI32 size)
{
    AP4_Position start, extra_data_start;
    stream.Tell(start);

    AP4_UI16 packet_count;
    stream.ReadUI16(packet_count);       // +2 bytes consumed
    AP4_UI16 reserved;
    stream.ReadUI16(reserved);           // +2 bytes consumed = 4 total

    for (AP4_UI16 i=0; i<packet_count; i++) {
        AP4_RtpPacket* packet = new AP4_RtpPacket(stream);  // +12 bytes each (minimum)
        m_Packets.Add(packet);
    }

    stream.Tell(extra_data_start);
    // BUG: if (extra_data_start - start) > size, this wraps to a huge positive number
    AP4_Size extra_data_size = size - (AP4_UI32)(extra_data_start-start);
    if (extra_data_size != 0) {
        m_ExtraData.SetDataSize(extra_data_size);   // allocates ~4 GB!
        stream.Read(m_ExtraData.UseData(), extra_data_size);
    }
}
```

### AP4_RtpPacket Header Layout (bytes consumed from stream)
| Field            | Size | Notes                     |
|------------------|------|---------------------------|
| relative_time    | 4    | uint32                    |
| pbit/xbit byte   | 1    | uint8                     |
| mbit/payload     | 1    | uint8                     |
| sequence_seed    | 2    | uint16                    |
| flags1 (discard) | 1    | uint8                     |
| flags2           | 1    | extra_flag, bframe, repeat|
| constructor_count| 2    | uint16                    |
| **Subtotal**     | **12** | (no extra block, no ctors)|

### Underflow Calculation
```
stsz declares:   size = 4
After parsing:   consumed = 4 (header) + 12 (1 packet) = 16 bytes
extra_data_size = (uint32)(4 - 16) = 0xFFFFFFF4  ← ~4.29 GB
```

### PoC File Structure
```
Offset   Size  Content
------   ----  -------
0        24    ftyp (major='mp42', compat='mp42','isom')
24       866   moov
  32     108     mvhd (timescale=1000, duration=1000)
  140    361     trak[1] - audio track (handler='soun', mp4a, 0 samples)
  501    389     trak[2] - hint track (handler='hint')
    509  92        tkhd (track_id=2)
    601  20        tref/hint (references track 1)
    621  269       mdia
      629 32         mdhd (timescale=90000)
      661 33         hdlr (type='hint')
      694 196        minf
        702 12          nmhd
        714 36          dinf
        750 140         stbl
          758 40          stsd (rtp  entry)
          798 24          stts (1 sample, delta=1)
          822 28          stsc (1 chunk)
          850 20          stsz ← sample_size=4 [MALFORMED]
          870 20          stco ← offset=898
890      24    mdat
  898    16      hint sample data:
                  packet_count=1 (0x0001)
                  reserved=0
                  packet: relative_time(4)+pbit/xbit(1)+mbit/payload(1)
                          +seq_seed(2)+flags1(1)+flags2(1)+ctor_count(2)
```

### Why mp42aac Cannot Trigger This
`mp42aac` only processes tracks with `AP4_Track::TYPE_AUDIO`. It never
instantiates `AP4_HintTrackReader` or calls `GetRtpSample()`. The hint track
is parsed (metadata only) during `new AP4_File(*input)`, but its sample data
is never read.

The correct tool to trigger this vulnerability is `mp4rtphintinfo`, which:
1. Iterates all tracks looking for `TYPE_HINT`
2. Creates an `AP4_HintTrackReader`  
3. In the constructor, calls `GetRtpSample(0)` → triggers the bug

### Expected Crash (with correct tool)
```
ASAN: heap-allocation-failure
    #0 operator new(unsigned long)
    #1 AP4_DataBuffer::SetDataSize(unsigned int)
    #2 AP4_RtpSampleData::AP4_RtpSampleData(AP4_ByteStream&, unsigned int)
    #3 AP4_HintTrackReader::GetRtpSample(unsigned int)
    #4 AP4_HintTrackReader::AP4_HintTrackReader(...)
```
or a segfault if ASAN is not present (OS OOM killer terminates the process).

### Reproduction
```bash
# With mp42aac (available binary - does NOT trigger the hint track path):
mp42aac vuln_003.mp4 /dev/null
# Expected: "ERROR: unsupported sample type" or normal exit

# With mp4rtphintinfo (would trigger the crash if it were built):
mp4rtphintinfo vuln_003.mp4
# Expected: ASAN heap-allocation-failure or process killed by OOM
```
