# VULN 001 - Heap OOB Read in MP3GAIN_UNDO APE Field Parsing

## Vulnerability

`ReadMP3APETag()` in `apetag.c` lines 229-242 parses the `MP3GAIN_UNDO` APE tag item
without checking that the value buffer is large enough. When `item_value_size=0`:

- `value = malloc(0+1)` allocates exactly 1 byte
- Line 230: `memcpy(tmpString, vp, 4)` reads 4 bytes from the 1-byte buffer (OOB)
- Line 234: `memcpy(tmpString, vp, 4)` where `vp = value+5` (11 bytes past valid memory)
- Line 238: `*vp` where `vp = value+10` (10 bytes past valid memory)

## PoC Construction

The PoC file (`vuln_001.mp3`, 153 bytes) contains:

1. **100 bytes** of fake MP3 prefix (MPEG sync word + zero padding)
2. **21 bytes** APE item: `\x00\x00\x00\x00` (vsize=0) + `\x00\x00\x00\x00` (flags=0) + `MP3GAIN_UNDO\x00`
3. **32 bytes** APEv2 footer: `APETAGEX` + version=2000 + length=53 + count=1 + flags=0 + 8-zero reserved

Key constraint satisfied: the boundary check at apetag.c:202 uses strict inequality
(`isize + 1 + vsize > remaining` => `13 > 13` = false), so parsing proceeds into
the MP3GAIN_UNDO branch despite the zero-length value.

## Expected Behavior

ASAN reports `heap-buffer-overflow` inside `__interceptor_memcpy` called from
`ReadMP3APETag`, confirming three out-of-bounds reads at offsets +0, +5, and +10
relative to the 1-byte `value` allocation.

## Verified Result

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in ReadMP3APETag
```
