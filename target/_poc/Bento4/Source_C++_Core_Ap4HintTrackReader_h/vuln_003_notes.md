# VULN 003 – Unsigned Integer Underflow in WriteSampleRtpData (GetSampleNum()-1)

## Vulnerability location

**File:** `Source/C++/Core/Ap4HintTrackReader.cpp`, line 331  
**Header:** `Source/C++/Core/Ap4HintTrackReader.h`  
**CWE:** CWE-191 (Integer Underflow / Wrap-around)

## Vulnerable code

```cpp
// AP4_HintTrackReader::WriteSampleRtpData() — line 331
AP4_Result result = referenced_track->GetSample(
    constructor->GetSampleNum()-1,   // <-- unsigned underflow when sample_num == 0
    sample);
```

`GetSampleNum()` returns `m_SampleNum` which is an `AP4_UI32` (unsigned 32-bit).
When the field in the hint sample contains the value `0`, the subtraction
`(AP4_UI32)0 - 1` wraps around to `0xFFFFFFFF`.  That enormous index is
passed directly to `referenced_track->GetSample()`, which accesses the
sample array far beyond its bounds.

## How the PoC works

### MP4 structure

```
ftyp  [20 B]       — brand: isom
mdat  [40 B]       — contains the 32-byte malicious hint sample data
moov
  mvhd
  trak  (track_id=1, handler='hint')   — HINT TRACK
    tkhd  (track_id=1)
    tref
      hint  (references track_id=2)   — m_MediaTrack = audio track
    mdia
      mdhd / hdlr(hint) / minf
        nmhd / dinf / stbl
          stsd  → 'rtp ' entry (RTP hint sample description)
          stts  → 1 sample, delta=1
          stsc  → first_chunk=1, 1 sample/chunk
          stsz  → 1 sample of 32 bytes
          stco  → offset 28 (start of hint data in mdat)
  trak  (track_id=2, handler='soun')   — AUDIO TRACK (for mp42aac)
    tkhd  (track_id=2)
    mdia
      mdhd / hdlr(soun) / minf
        smhd / dinf / stbl
          stsd  → mp4a (AAC-LC) entry
          stts/stsc/stsz/stco  — empty (0 samples)
```

### Malicious hint sample data (32 bytes in mdat)

```
packet_count = 1
  Packet header (12 B):
    relative_time=0, pbit/xbit=0x80, mbit/payload=0, seq_seed=0
    ignored_byte=0, flags=0, constructor_count=1
  SAMPLE constructor (16 B):
    type=0x02 (SAMPLE)
    track_ref_index=0x00  → referenced_track = m_MediaTrack (audio, track_id=2)
    length=0x0000
    sample_num=0x00000000  ← UNDERFLOW TRIGGER: 0 - 1 = 0xFFFFFFFF
    sample_offset=0x00000000
    (4 bytes padding: bytes_per_block=1, samples_per_block=1)
```

### Call path (when AP4_HintTrackReader is used)

```
AP4_HintTrackReader::GetNextPacket()
  -> BuildRtpPacket(packet, packet_data)
    -> WriteSampleRtpData(constructor, stream)
       constructor->GetSampleNum() == 0
       (AP4_UI32)0 - 1 == 0xFFFFFFFF          ← integer underflow
       referenced_track->GetSample(0xFFFFFFFF, sample)  ← OOB
```

## Expected ASAN output (when triggered)

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow or SEGV
WRITE of size N at 0x...
    #0 ... AP4_AtomSampleTable::GetSample(...)
    #1 ... AP4_Track::GetSample(...)
    #2 ... AP4_HintTrackReader::WriteSampleRtpData(...)
    #3 ... AP4_HintTrackReader::BuildRtpPacket(...)
    #4 ... AP4_HintTrackReader::GetNextPacket(...)
```

## Why mp42aac does not trigger the crash

`mp42aac` looks only for `TYPE_AUDIO` tracks and calls `WriteSamples()` on them.
It does **not** create an `AP4_HintTrackReader` and never calls `GetNextPacket()`.
Confirmed: `nm mp42aac | grep HintTrackReader` returns no symbols.

The malicious MP4 is correctly structured to trigger the underflow in any binary
that does exercise `AP4_HintTrackReader` (e.g., `mp4rtphintinfo`, `mp4info`, or
a fuzzer harness that instantiates the hint reader).

## Fix recommendation

Add a zero-check before the subtraction in `WriteSampleRtpData`:

```cpp
AP4_UI32 sample_num = constructor->GetSampleNum();
if (sample_num == 0) return AP4_ERROR_INVALID_FORMAT;
AP4_Result result = referenced_track->GetSample(sample_num - 1, sample);
```
