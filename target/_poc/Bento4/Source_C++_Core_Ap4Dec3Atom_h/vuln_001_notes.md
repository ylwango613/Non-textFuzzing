# VULN-001: Heap Over-Read in AP4_Dec3Atom Constructor

## Summary
- **File**: `Bento4/Source/C++/Core/Ap4Dec3Atom.cpp`, lines 96-104
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Binary**: `mp42aac`

## Root Cause

In `AP4_Dec3Atom::AP4_Dec3Atom(AP4_UI32 size, const AP4_UI08* payload)`:

1. `payload_size = size - 8` (box header is 8 bytes)
2. `substream_count = 1 + (payload[1] & 7)` — max 8
3. `payload += 2; payload_size -= 2` — skip DataRate bytes
4. Loop `for i in 0..substream_count`:
   - Guard: `if (payload_size < 3)` — with payload_size=3 this is FALSE (not `<= 3`)
   - Reads `payload[0]`, `payload[1]`, `payload[2]` — within bounds
   - Reads `payload[2]` bits[4:1] → `num_dep_sub`
   - **If `num_dep_sub != 0`**: reads `payload[3]` → **OOB** (only 3 bytes remain: indices 0,1,2)
   - `payload_size -= 4` → unsigned wrap: `3 - 4 = 0xFFFFFFFC`
   - Next iteration: `0xFFFFFFFC < 3` → FALSE → 7 more OOB iterations follow

## Trigger Conditions

`dec3` box with size=13 (5-byte payload):
```
Byte 0: 0x00  — DataRate high byte
Byte 1: 0x07  — DataRate low | substream_count bits[2:0]=7 → count=8
Byte 2: 0x00  — loop byte 0 (fscod/bsid bits)
Byte 3: 0x00  — loop byte 1 (bsmod/acmod/lfeon bits)
Byte 4: 0x02  — loop byte 2: (0x02>>1)&0xF=1 → num_dep_sub=1 → triggers OOB read of byte 5
```

After DataRate skip: payload_size=3, remaining = bytes[2,3,4].
Reading payload[3] (= original byte 5) is past the end of the allocation.
Unsigned wrap then allows 7 more loop iterations reading further OOB.

## PoC Structure

Minimal MP4:
```
ftyp [mp42, version=0, compat: mp42/isom]
moov
  mvhd [version=0]
  trak
    tkhd [version=0, flags=3]
    mdia
      mdhd [version=0]
      hdlr [soun]
      minf
        smhd
        dinf
          dref
            url  [flags=1, self-contained]
        stbl
          stsd
            ec-3  [EC-3 audio sample entry]
              dec3 [size=13, crafted payload]
          stts [1 sample, delta=1024]
          stsc [1 entry]
          stsz [1 sample, size=100]
          stco [1 chunk offset]
mdat [100 bytes dummy audio]
```

## Expected Result

AddressSanitizer detects a heap-buffer-overflow (read) at the `payload[3]` access on the first loop iteration,
with up to 7 subsequent OOB reads in later iterations due to unsigned integer wrap-around in `payload_size`.
