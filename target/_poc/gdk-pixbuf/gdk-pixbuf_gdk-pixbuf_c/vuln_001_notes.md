# VULN 001 - Heap Buffer Overflow via RLE Repeat-Run Zero-Length

## Summary
A heap buffer overflow exists in `gdk_pixbuf_from_pixdata()` in the gdk-pixbuf library. When an RLE-encoded GdkPixdata stream contains a repeat-run byte of `0x80`, the count field is extracted as `0x80 & 0x7f = 0`. The do-while loop then attempts to write `length` (0) pixels but immediately decrements `length` as an unsigned integer, causing it to underflow to `UINT_MAX` (~4.29 billion). This results in approximately 12–17 GB of heap writes past the allocated buffer.

## Affected Code
- **File**: `gdk-pixbuf/gdk-pixdata.c`
- **Function**: `gdk_pixbuf_from_pixdata()`
- **Mechanism**: Unsigned integer underflow in the RLE repeat-run decode loop when count = 0.

## Root Cause
In the RLE decoding loop inside `gdk_pixbuf_from_pixdata()`:
```c
if (rbuf & 0x80)  // repeat-run
{
    length = (rbuf & 0x7f);  // length = 0 when rbuf = 0x80
    do {
        // write `bpp` bytes (pixel value)
        // decrement: length-- on an unsigned int with value 0 → UINT_MAX
    } while (--length);
}
```
When `rbuf = 0x80`, `length = 0`. The `do { } while (--length)` loop writes once, then `--length` underflows from 0 to `UINT_MAX`, causing the loop to continue for ~4.29 billion iterations writing far past the allocated heap buffer.

## Attack Vector
1. Craft a `.gdkp` file with a valid GdkPixdata header (magic `GdkP`, RLE+RGB encoding).
2. Place `0x80` as the first RLE byte in the pixel data, followed by any 3-byte RGB pixel.
3. Pass the file to any program using `gdk_pixbuf_new_from_file()` or the gdkp loader.

## Reproduction
```bash
python3 vuln_001_gen.py   # generates vuln_001.gdkp
bash vuln_001_run.sh      # triggers the overflow
```

## ASAN Crash Output (Summary)
```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 3 at 0x504000000680
  #1 gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xacede)
  #2 try_load (libgdk_pixbuf-2.0.so.0+0xc74fb)
  #3 pixdata_image_load_increment
  #4 generic_load_incrementally
  #5 _gdk_pixbuf_generic_image_load
  #6 gdk_pixbuf_new_from_file
  #7 main (gdk-pixbuf-pixdata)
```
Heap region: 48-byte allocation overflowed (4x4 RGB = 48 bytes), first OOB write is 3 bytes past end.

## Fix Note
The bug can be fixed by checking `length == 0` before entering the RLE repeat loop, or by using a signed integer comparison. A minimal fix:
```c
length = rbuf & 0x7f;
if (length == 0) { /* handle error or skip */ continue; }
```

## CVE Reference
This matches the class of bugs described in various gdk-pixbuf advisories. The specific trigger (0x80 byte, zero-count underflow) is a classic unsigned integer underflow leading to heap overflow.
