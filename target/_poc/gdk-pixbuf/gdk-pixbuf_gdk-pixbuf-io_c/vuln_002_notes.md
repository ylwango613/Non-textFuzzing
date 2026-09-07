# VULN-002 – GdkPixdata RLE Decoder Heap OOB Read

## Summary

A heap out-of-bounds read exists in the RLE decode loop of
`gdk_pixbuf_from_pixdata()` in `gdk-pixdata.c` (lines 459–493).

## Root Cause

The loop terminates when the *output* pointer `image_buffer` reaches
`image_limit = data + rowstride * height`, but the *input* pointer
`rle_buffer` is never checked against the end of the pixel data.
An attacker-controlled `.gdkp` file with fewer RLE bytes than the declared
output dimensions can exhaust the pixel data mid-loop, causing
`rle_buffer` to read beyond the heap allocation.

```c
while (image_buffer < image_limit)
{
    guint length = *(rle_buffer++);   // NO bounds check on rle_buffer
    ...
    rle_buffer += length;             // NO bounds check
}
```

## PoC File Layout (28 bytes)

| Offset | Size | Value      | Meaning                         |
|--------|------|------------|---------------------------------|
| 0      | 4    | 47646b50   | Magic: "GdkP"                   |
| 4      | 4    | 0000001c   | Total length = 28               |
| 8      | 4    | 02010001   | RGB, RLE, 8-bit samples         |
| 12     | 4    | 00000003   | rowstride = 3                   |
| 16     | 4    | 00000001   | width = 1                       |
| 20     | 4    | 00000003   | height = 3                      |
| 24     | 4    | 01 AA BB CC| 4 bytes of RLE pixel data       |

## Exploit Trace

- `image_limit = rowstride * height = 3 * 3 = 9` output bytes expected
- Iteration 1: token `0x01` → non-run, raw copy 1 pixel (3 bytes).
  `image_buffer` advances from 0 to 3; `rle_buffer` advances from offset 24
  to offset 28 (the very end of the file / heap allocation).
- Iteration 2: `image_buffer (3) < image_limit (9)` → loop continues.
  `*(rle_buffer++)` reads **byte 29** — one past the end of the allocation.
  ASAN reports: `READ of size 1` / `heap-buffer-overflow`.

## Validation Checks Bypassed

The deserializer's pre-check `stream_length < pixdata->length - 24` becomes
`28 < 28 - 24 = 4` → FALSE → passes, even though pixel data is insufficient
to satisfy the declared geometry.

## Impact

- Heap OOB read of arbitrary length (attacker controls `height` and `rowstride`)
- Potentially reads sensitive heap contents; depending on allocator layout
  could lead to information disclosure
- Triggered by loading an untrusted `.gdkp` file through any application
  that uses `gdk_pixbuf_from_pixdata()` or the `.gdkp` pixdata loader

## Files

| File                   | Purpose                              |
|------------------------|--------------------------------------|
| `vuln_002_gen.py`      | Generate `vuln_002.gdkp`             |
| `vuln_002.gdkp`        | Malicious pixdata file (28 bytes)    |
| `vuln_002_run.sh`      | Run gdk-pixbuf-pixdata + check ASAN  |
| `vuln_002_result.txt`  | Program stdout/stderr                |
| `asan_002.log.<pid>`   | ASAN report                          |
| `vuln_002_status.txt`  | VERIFIED_CRASH / UNVERIFIED / ERROR  |
| `vuln_002_notes.md`    | This file                            |
