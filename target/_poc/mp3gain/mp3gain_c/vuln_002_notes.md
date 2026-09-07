# VULN 002 — apetag.c heap-buffer-over-read (MP3GAIN_MINMAX)

## Root Cause

`ReadMP3APETag` (apetag.c:244–265) processes an APE item named
`MP3GAIN_MINMAX` without verifying that the item's value buffer is
large enough before performing fixed-size `memcpy` calls.

```c
value = (char*)malloc(vsize + 1);   // vsize=0  →  1-byte allocation
memcpy(value, p+isize+1, vsize);    // copies 0 bytes — safe so far
value[vsize] = 0;                   // value[0]='\0' — fine

// Later, unconditionally:
vp = value;
memcpy(tmpString, vp, 3);           // reads 3 bytes from 1-byte heap chunk  ← OOB
```

## PoC Approach

- Craft a minimal 417-byte MPEG-1 Layer-3 frame so mp3gain processes
  the file as a valid MP3.
- Append an APEv2 tag (footer-only, no header) containing a single item:
  - key  = `MP3GAIN_MINMAX`
  - vsize = 0  (empty value)
- The bounds check at line 202 passes because
  `isize(14) + 1 + vsize(0) == remaining(15)` is not strictly greater.
- mp3gain allocates a 1-byte buffer for the value, then reads 3 bytes
  from it → heap-buffer-over-read detectable by AddressSanitizer.

## Files

| File | Purpose |
|---|---|
| `vuln_002_gen.py` | Generates the crafted `vuln_002.mp3` |
| `vuln_002_run.sh` | Runs mp3gain under ASAN and captures output |
| `vuln_002_result.txt` | mp3gain output + filtered ASAN errors |
| `vuln_002_status.txt` | Single-keyword verdict |
