# VULN 001: mp3gain apetag.c heap-buffer-over-read

## Summary

`ReadMP3APETag` in `apetag.c` allocates `value = malloc(vsize+1)` and copies
`vsize` bytes into it. When the APE item name is `"MP3GAIN_UNDO"` and `vsize=0`,
the allocation is only 1 byte, yet the code immediately performs:

```c
vp = value;
memcpy(tmpString, vp, 4);   // reads 4 bytes from a 1-byte heap buffer
```

This is a heap-buffer-over-read of 3 bytes (reads 4, only 1 valid).

## Trigger Conditions

- APEv2 tag present at end of file
- Single APE item with key = `MP3GAIN_UNDO`
- Item value size (`vsize`) = 0

## PoC Construction

The crafted file `vuln_001.mp3` contains:

1. A minimal MPEG1 Layer3 frame (417 bytes, header `FF FB 90 00`) so that
   mp3gain opens and processes the file.
2. One APEv2 item: `{vsize=0, flags=0, key="MP3GAIN_UNDO\0", value=b""}`
   (21 bytes total).
3. An APEv2 footer (32 bytes) with `Length = 53`, `TagCount = 1`,
   `Flags = 0` (footer-only, no header).

No custom C harness is required; the standard `mp3gain` binary reads APE tags
directly from the file.

## Expected ASAN Output

Under an AddressSanitizer build the run should report:
```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at ...
```
because `memcpy(tmpString, vp, 4)` reads past the end of the 1-byte allocation.
