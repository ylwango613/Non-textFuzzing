# VULN 001 - Heap OOB Read via AP4_BitReader::ReadCache in dac4 DSI Parsing

## Summary

**CWE**: CWE-125 (Out-of-bounds Read)  
**File**: `Source/C++/Core/Ap4Dac4Atom.cpp` lines 76-176; `Ap4Utils.cpp` line ~430  
**Binary**: `mp42aac`

## Root Cause

`AP4_BitReader::ReadCache()` reads a 4-byte word from `m_Buffer.GetData() + m_Position` without checking whether at least 4 bytes remain in the buffer. In `AP4_Dac4Atom`'s constructor, when `ac4_dsi_version == 1`, the parser reads several large fields from the bit stream:

1. `bitstream_version` (7 bits)
2. `fs_index` (1 bit)
3. `frame_rate_index` (4 bits)
4. `n_presentations` (9 bits) — **controlled by attacker**
5. `bit_rate_mode` (2 bits)
6. `bit_rate` (32 bits)
7. `bit_rate_precision` (32 bits) — **reads past buffer end**

With an 11-byte (88-bit) payload and `n_presentations=511`, the parser reaches `bit_rate_precision` starting at bit 58. This read spans bits 58–89, crossing the 88-bit boundary. When `ReadCache()` tries to load a 4-byte word from byte offset 10 (the last valid byte is index 10), it reads bytes 10, 11, 12, 13 — of which bytes 11–13 are past the allocated buffer.

## Bit Layout of the 11-byte dac4 Payload

```
bits  0- 2: ac4_dsi_version   = 1   → 001
bits  3- 9: bitstream_version = 1   → 0000001
bit  10   : fs_index          = 0   → 0
bits 11-14: frame_rate_index  = 0   → 0000
bits 15-23: n_presentations   = 511 → 111111111
bits 24-87: zeros (8 bytes padding)
```

Raw bytes: `20 41 FF 00 00 00 00 00 00 00 00`

## Why 11 Bytes

The constructor at line 73 has:
```cpp
if (payload_size < 11) return;
```
So 11 bytes is the minimum to enter the vulnerable parsing path. The buffer is therefore exactly 88 bits, but the parser needs 90+ bits before the byte-align step, triggering the OOB.

## MP4 Structure

The PoC constructs a structurally valid MP4 to ensure the file is parsed deeply enough to reach the dac4 box:

```
ftyp (mp42)
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr (soun)
      minf
        smhd
        dinf → dref → url (self-contained)
        stbl
          stsd
            ac-4 (audio sample entry)
              dac4 [11-byte malicious payload]
          stts, stsc, stsz, stco (empty)
```

## Trigger

```bash
mp42aac vuln_001.mp4 /dev/null
```

Parsing the MP4 file causes Bento4 to instantiate `AP4_Dac4Atom` for the `dac4` box, triggering the OOB read in `ReadCache()`.

## Expected ASAN Output

AddressSanitizer should report a `heap-buffer-overflow` on a READ of size 4 inside `AP4_BitReader::ReadCache`, with the call stack originating from `AP4_Dac4Atom::AP4_Dac4Atom`.
