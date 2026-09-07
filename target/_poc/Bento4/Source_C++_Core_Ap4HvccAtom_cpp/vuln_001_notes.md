# VULN 001 - Off-by-One Heap OOB Read in hvcC Atom Parsing

## Vulnerability

**File**: `Bento4/Source/C++/Core/Ap4HvccAtom.cpp`  
**Function**: `AP4_HvccAtom::AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload)`  
**Lines**: 255, 282  
**CWE**: CWE-125 (Out-of-bounds Read)

### Root Cause

The guard at line 255:
```cpp
if (payload_size < 22) return;
```

When `payload_size == 22`, the condition evaluates to `(22 < 22)` which is **false**, so execution is NOT stopped. The code then proceeds to access `payload[0]` through `payload[21]` (all valid for a 22-byte buffer), but then at line 282:

```cpp
AP4_UI08 num_seq = payload[22];  // OOB! Valid indices are 0..21 only
```

This reads 1 byte past the end of the allocated buffer — a classic off-by-one error. The guard should be `if (payload_size < 23) return;` (or equivalently `if (payload_size <= 22) return;`) to protect this access.

## MP4 Construction

The PoC constructs a minimal MP4 with the following atom hierarchy:

```
ftyp  (isom brand)
moov
  mvhd  (version 0)
  trak
    tkhd  (version 0, track_id=1, video 320x240)
    mdia
      mdhd  (version 0, timescale=90000)
      hdlr  (vide handler)
      minf
        vmhd  (video media header, flags=1)
        dinf
          dref
            url   (self-contained, flags=1)
        stbl
          stsd  (entry_count=1)
            hvc1  (HEVC visual sample entry)
              hvcC  [30 bytes total = 8 header + 22 payload]  <-- TRIGGER
          stts  (empty)
          stsc  (empty)
          stsz  (empty)
          stco  (empty)
```

The critical box is the `hvcC` atom inside the `hvc1` sample entry:
- Total size: **30 bytes** (size field = 30)
- Header: 8 bytes (`size` uint32 + `hvcC` 4-char type)
- Payload: **22 bytes** (all zeros)

When Bento4 parses this atom, it computes:
```
payload_size = 30 - 8 = 22
```

The guard `if (payload_size < 22) return;` evaluates to `(22 < 22) = false` and **does not return**. Execution reaches line 282 and reads `payload[22]`, which is 1 byte past the end of the valid 22-byte buffer region.

## Expected ASAN Output

When compiled with AddressSanitizer, the binary should report:

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in AP4_HvccAtom::AP4_HvccAtom(unsigned int, unsigned char const*)
       Bento4/Source/C++/Core/Ap4HvccAtom.cpp:282
```

The error type is `heap-buffer-overflow` with access type `READ` of size 1 (1 byte).
