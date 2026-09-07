# VULN 001 - Heap OOB Read in gdip_bitmap_get_frame_delay

## Vulnerability Summary

**Name**: Heap OOB Read via Inflated item_count in gdip_bitmap_get_frame_delay  
**CWE**: CWE-125 (Out-of-bounds Read)  
**Location**: `io-gdip-utils.c`, lines 491-499, function `gdip_bitmap_get_frame_delay()`  
**Loader**: io-gdip-gif (Windows GDI+ based GIF loader)

## Vulnerable Code

```c
if (Ok == GdipGetPropertyItemSize ((GpImage *)bitmap, PropertyTagFrameDelay, &item_size)) {
    PropertyItem *item;
    item = (PropertyItem *)g_try_malloc (item_size);
    if (Ok == GdipGetPropertyItem ((GpImage *)bitmap, PropertyTagFrameDelay, item_size, item)) {
      item_count = item_size / sizeof(long);          // BUG: item_size includes PropertyItem header
      *delay = ((long *)item->value)[(frame < item_count) ? frame : item_count - 1];  // OOB access
      success = TRUE;
    }
    g_free (item);
}
```

## Root Cause

`GdipGetPropertyItemSize()` returns `item_size` = `sizeof(PropertyItem)` + `(n_delays * sizeof(long))`.  
`sizeof(PropertyItem)` is typically 16 bytes on Windows.

The code computes `item_count = item_size / sizeof(long)`, which over-counts by `sizeof(PropertyItem)/sizeof(long)` = 4 on 32-bit or 2 on 64-bit. However, `item->value` points past the header to only `n_delays` actual delay values.

When a GIF has more frames than GCE delay entries (e.g., 2 frames but 1 delay), the guard `(frame < item_count)` may pass even for an OOB index because `item_count` is inflated.

## Trigger Conditions

- Animated GIF with 2+ frames
- Only 1 Graphic Control Extension (1 delay entry in PropertyTagFrameDelay)
- n_frames=2 but actual delay array has 1 entry; `frame=1` causes OOB

## GIF Structure for PoC

```
GIF89a
Logical Screen Descriptor (2x2)
Global Color Table (4 colors)
Netscape Application Extension (loop control)
[Frame 1] Graphic Control Extension (delay=100) + Image Descriptor + Image Data
[Frame 2] Image Descriptor + Image Data (NO GCE - intentionally omitted)
Trailer
```

## Attack Vector

External: `gdk_pixbuf_new_from_file()` → `gdk_pixbuf__gdip_image_stop_load()` → `stop_load()` → `gdip_bitmap_get_frame_delay(bitmap, 1, &frame_delay)` → OOB read at `((long*)item->value)[1]`

## Platform Availability

**This loader is Windows-only.** The GDI+ (gdiplus) loaders in gdk-pixbuf are conditionally compiled only when `os_win32=yes` (see `configure.ac`):

```
AM_CONDITIONAL(BUILD_GDIPLUS_LOADERS, [ test x$os_win32 = xyes && test x$with_gdiplus != xno ])
```

On Linux, the io-gdip-gif loader is not compiled or available. The vulnerability cannot be triggered on Linux builds.
