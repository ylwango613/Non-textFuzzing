# VULN 003 - Heap OOB Read in MP3GAIN_ALBUM_MINMAX APE Field Parsing

## Vulnerability

In `apetag.c` `ReadMP3APETag()` at lines 254-264, when an APE item named
`MP3GAIN_ALBUM_MINMAX` is parsed with `item_value_size=0`:

1. `value = malloc(vsize+1) = malloc(1)` — only 1 byte allocated.
2. **Line 258**: `memcpy(tmpString, vp, 3)` where `vp = value` — reads 3 bytes
   from a 1-byte heap buffer → OOB read of 2 bytes past allocation.
3. **Line 262**: `memcpy(tmpString, vp, 3)` where `vp = value + 4` — reads 3
   bytes starting 4 bytes past the 1-byte allocation → OOB read of 7 bytes.

This is the same pattern as VULN 002 (MP3GAIN_MINMAX) but for the album variant.

## PoC Construction

The file `vuln_003.mp3` contains:
- One minimal fake MPEG1 Layer3 frame (417 bytes) to satisfy basic file structure.
- One APEv2 item: `item_value_size=0`, `item_flags=0`,
  `item_key="MP3GAIN_ALBUM_MINMAX\0"`, `item_value=""` (empty).
- An APEv2 footer (footer-only, no header) with `tag_size = 29 + 32 = 61`.

The APE tag parser reads the footer from the last 32 bytes of the file,
validates the "APETAGEX" magic, then reads `tag_size - 32 = 29` bytes of items
before the footer. The single item passes all bounds checks (isize+1+vsize == 21
<= remaining=21), then the name match triggers the vulnerable `memcpy` calls.

## Observed Behavior

ASAN reports `heap-buffer-overflow` in `__interceptor_memcpy` at the first
`memcpy(tmpString, vp, 3)` call (line 258), confirming the OOB read.
