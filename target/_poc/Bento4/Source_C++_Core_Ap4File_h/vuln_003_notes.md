# VULN 003 PoC Notes — stsz atom incorrect overflow guard

## Vulnerability Summary

**File**: `Source/C++/Core/Ap4StszAtom.cpp`, line 78  
**Guard**: `if (m_SampleCount > (size-8)/4)` — off by 12 bytes  
**Should be**: `if (m_SampleCount > (size-20)/4)`

### Why the guard is wrong

At the point the guard is reached, the stream has already consumed:

| Bytes | Purpose |
|-------|---------|
| 4 | box size field (read by atom factory) |
| 4 | box type 'stsz' (read by atom factory) |
| 4 | version (1B) + flags (3B) (read by ReadFullHeader) |
| 4 | sample_size (read in constructor) |
| 4 | sample_count (read in constructor) |
| **20 total** | |

So available entry bytes = `size - 20`, max entries = `(size-20)/4`.  
The buggy guard uses `(size-8)/4` — subtracts only 8 instead of 20, allowing
3 extra entries (12 extra bytes).

## PoC Design

### File structure (104 bytes total)

```
ftyp (20B)
moov (84B)
  trak (76B)
    mdia (68B)
      minf (60B)
        stbl (52B)
          stsz (28B)  ← vulnerable atom
          stco (16B)  ← immediately follows; first 12 bytes are read OOB by stsz
```

### stsz box layout (28 bytes)

```
Offset  Size  Value         Meaning
0       4     0x0000001C    box size = 28
4       4     'stsz'        box type
8       1     0x00          version = 0
9       3     0x000000      flags = 0
12      4     0x00000000    sample_size = 0  → variable-size mode, enables entry table
16      4     0x00000005    sample_count = 5  → passes buggy guard
20      4     0xDEADBEEF    entry[0] (legitimate, within atom)
24      4     0xCAFEBABE    entry[1] (legitimate, within atom)
                             ↑ atom ends here (28 bytes) ↑
```

### OOB read (12 bytes from stco header)

```
Offset  Size  Value       Source
28      4     0x00000010  stco box size = 16   ← OOB read byte 0-3
32      4     'stco'      stco box type         ← OOB read byte 4-7
36      4     0x00000000  stco version+flags    ← OOB read byte 8-11
```

`stream.Read(buffer, 20)` fills the 20-byte heap buffer:
- bytes 0-7: `DEADBEEF CAFEBABE` (real stsz entries)
- bytes 8-19: `00000010 7374636F 00000000` (stco size, 'stco', ver+flags)

## Why ASAN Does Not Trigger

The heap buffer `new unsigned char[sample_count*4]` is correctly sized at 20 bytes
for `sample_count=5`. All 20 bytes written by `stream.Read` land within the
allocated region — no heap boundary is crossed.

The violation is at the **stream / file-format protocol level**: the parser reads
12 bytes that the MP4 box header says belong to the NEXT atom. ASAN instruments
heap/stack memory accesses, not file I/O calls (fread/read syscalls). Thus ASAN
reports nothing despite the protocol-level OOB.

## Impact

- **Information disclosure**: In a streaming/network context the parser silently
  reads data outside the declared atom boundary. An attacker can embed 12 bytes
  of arbitrary data in the stco box header area and have it processed as stsz
  sample-size entries.
- **Logical corruption**: The three extra "sample sizes" parsed from the following
  box's header corrupt the `m_Entries` array used later for seeking and decoding.

## Verdict

**UNVERIFIED** — the vulnerable code path is exercised (sample_count=5 passes the
buggy guard, stream.Read consumes 12 bytes past atom boundary) but there is no
observable crash or ASAN report because the flaw is a stream-level OOB.
