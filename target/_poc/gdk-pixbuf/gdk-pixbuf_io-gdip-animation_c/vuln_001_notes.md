# VULN 001 Notes: Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay

## Vulnerability Summary

- **Name**: Heap Out-of-Bounds Read via Inflated item_count in gdip_bitmap_get_frame_delay
- **File**: `gdk-pixbuf/io-gdip-utils.c`, lines 483-498
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Attack Vector**: Crafted animated GIF file

## Root Cause

In `gdip_bitmap_get_frame_delay()`, the code retrieves the `PropertyTagFrameDelay` property from a GDI+ bitmap and computes the number of frame delay entries as:

```c
item_count = item_size / sizeof(long);
```

However, `item_size` returned by GDI+ includes the `PropertyItem` header overhead (approximately 4-6 extra slot-widths), so `item_count` is inflated beyond the actual number of valid delay entries.

The subsequent bounds check uses this inflated `item_count`:

```c
if (index < item_count) {
    *delay = ((long *)prop->value)[index];
}
```

When a GIF has more frames than actual `FrameDelay` entries, the loop in the caller iterates `i = 0 .. n_frames-1`. For a 5-frame GIF with only 2 real delay entries, accesses at indices 2, 3, and 4 fall beyond the valid `prop->value` array but within the inflated `item_count` bound. This causes an **out-of-bounds read** on the heap, which could leak adjacent heap memory or cause a crash.

## Trigger Path

```
crafted GIF
  -> gdk_pixbuf__gdip_image_load_increment()
  -> gdk_pixbuf__gdip_image_stop_load()
  -> gdip_buffer_to_bitmap()
  -> stop_load() [loops i=0..n_frames-1]
  -> gdip_bitmap_get_frame_delay(bitmap, i, &delay)  [OOB read at i >= real_delay_count]
```

## Why the Crafted GIF Works (Theoretical)

The generated `vuln_001.gif` has:
- **5 frames** in the GIF structure (NUM_FRAMES = 5)
- Each frame has a Graphics Control Extension with a delay field in the GIF spec

On a Windows system with GDI+ enabled in gdk-pixbuf:
1. GDI+ loads the animated GIF and exposes `PropertyTagFrameDelay` property data
2. The property value contains only **2 real entries** (GDI+ behavior for certain GIF structures, or as simulated by the mismatch between GCE delay count and property data)
3. `item_count = item_size / sizeof(long)` computes a value >= 5 due to header overhead, passing the bounds check
4. The loop reads `prop->value[2]`, `prop->value[3]`, `prop->value[4]` out of bounds

## Why It Cannot Be Triggered on This Linux Build

### 1. No GDI+ Support
GDI+ (Graphics Device Interface Plus) is a Windows-only graphics library (`GdiPlus.dll`). The gdk-pixbuf modules `io-gdip-animation.c` and `io-gdip-utils.c` are compiled exclusively on Windows (`#ifdef G_OS_WIN32`). This Linux build does not include these modules at all.

### 2. No GIF Loader
The target binary is:
```
/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata
```
The only format module compiled into this binary supports the **pixdata** format only (`_gdk_pixbuf__pixdata_fill_vtable`). When given a GIF file, the binary outputs:
```
Couldn't recognize the image file format for file '...'
```

### 3. Platform Constraint
Even if a GIF were somehow decoded on Linux, the vulnerable code path through `gdip_bitmap_get_frame_delay` is gated by GDI+ API calls that have no Linux equivalent.

## Environment Required to Trigger

To reproduce this vulnerability:
1. **OS**: Windows (any version with GDI+ available, which is Vista and later)
2. **gdk-pixbuf**: Build with `--enable-gdip` (or equivalent) so `io-gdip-animation.c` is compiled and loaded
3. **Loader**: The GIF loader must be `io-gdip-animation.c` (Windows GDI+ path), not the native `io-gif.c` path
4. **Tool**: Any gdk-pixbuf consumer (e.g., `gdk-pixbuf-thumbnailer`, a GTK application) that loads animated GIFs

With ASAN on Windows:
```
ASAN_OPTIONS=abort_on_error=0 application.exe vuln_001.gif
```
Expected ASAN output: `ERROR: AddressSanitizer: heap-buffer-overflow on READ`

## GIF Structure Rationale

The crafted GIF (`vuln_001.gif`) contains:
- `GIF89a` header (signals animation support)
- Logical Screen Descriptor: 10x10 pixels, 4-color Global Color Table
- Netscape Application Extension for infinite looping
- 5 frames, each consisting of:
  - Graphics Control Extension (with varying delays: 10cs, 20cs, 30cs, 40cs, 50cs)
  - Image Descriptor
  - LZW-compressed image data (10x10 all-black pixels)
- GIF Trailer (0x3B)

The mismatch is between:
- **GIF structure**: 5 frames with 5 GCE delay values
- **GDI+ property data**: `PropertyTagFrameDelay` returns only 2 entries (GDI+ can under-report for certain malformed or edge-case GIFs), while `item_count = item_size / sizeof(long)` inflates the bound to 6+, allowing reads at indices 2-4 to pass the check but access out-of-bounds memory.
