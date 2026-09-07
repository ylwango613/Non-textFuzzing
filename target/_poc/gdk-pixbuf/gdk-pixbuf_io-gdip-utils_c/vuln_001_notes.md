# VULN_001 — Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay

## Vulnerability Summary

| Field | Detail |
|-------|--------|
| ID | VULN_001 |
| CWE | CWE-125 (Out-of-bounds Read) |
| File | `io-gdip-utils.c` |
| Lines | 491–504 |
| Function | `gdip_bitmap_get_frame_delay(GpBitmap *bitmap, guint frame, guint *delay)` |
| Platform | Windows only (GDI+ integration) |

## Root Cause Analysis

The vulnerable code path is in `gdip_bitmap_get_frame_delay`:

```c
// Line ~491
GpStatus status;
UINT item_size;
PropertyItem *item;
guint item_count;

status = GdipGetPropertyItemSize(bitmap, PropertyTagFrameDelay, &item_size);
// item_size = sizeof(PropertyItem) + (actual_delay_count * sizeof(LONG))
//           = 16 + N*4  (on Windows, PropertyItem header is 16 bytes)

item = g_malloc(item_size);
GdipGetPropertyItem(bitmap, PropertyTagFrameDelay, item_size, item);

// BUG HERE (line ~496):
item_count = item_size / sizeof(long);
// On 64-bit: sizeof(long) = 8
// item_count = (16 + N*4) / 8  -- inflated by the struct header
// For N=1: item_count = 20 / 8 = 2  (should be 1)
// For N=2: item_count = 24 / 8 = 3  (should be 2)

if (frame < item_count) {
    *delay = ((long *)item->value)[frame];   // may read into struct padding
} else {
    // Fallback: use last entry
    *delay = ((long *)item->value)[item_count - 1]; // OOB read
}
```

The inflated `item_count` means the bounds check `frame < item_count` passes
for frame values that exceed the actual number of delay values stored in
`item->value`. The fallback `item_count - 1` index then reads past the end of
the allocated buffer.

## Attack Vector

1. Create an animated GIF with N frames (e.g. N=3).
2. The GIF's PropertyTagFrameDelay metadata contains only 1 delay value.
3. On a Windows/GDI+ build, `GdipGetPropertyItemSize` returns
   `item_size = 16 + 1*4 = 20`.
4. `item_count = 20 / 8 = 2` (inflated from actual 1).
5. Accessing frame 1 passes the `frame < item_count` check (1 < 2 = true),
   causing an OOB read into adjacent heap memory via `item->value[1]`.

## PoC Construction (vuln_001_gen.py)

The generated `vuln_001.gif` is a 3-frame animated GIF (1×1 pixel) with:
- Frame 0: Graphic Control Extension with delay=10 centiseconds
- Frame 1: Graphic Control Extension with delay=0 centiseconds
- Frame 2: Graphic Control Extension with delay=0 centiseconds

In a correct PropertyTagFrameDelay scenario, the GIF file would store only
1 delay value in its metadata to simulate the OOB condition. The script
sets delay=0 for frames 1 and 2 to signal the "missing" entries.

## Why This Cannot Be Triggered on This Linux Build

This Linux build was compiled with:
```
./configure --without-libtiff --without-libjasper --disable-modules
```

As a result:
- None of the `io-gdip-*.c` files are compiled.
- The GDI+ integration (`GdipGetPropertyItemSize`, `GdipGetPropertyItem`,
  `gdip_bitmap_get_frame_delay`) does not exist in this binary.
- The `gdk-pixbuf-pixdata` binary supports only the `pixdata` format
  (`_gdk_pixbuf__pixdata_fill_vtable`). It does not have a GIF loader.
- When fed a GIF file, it will fail with an unsupported format error,
  not an OOB read.

The vulnerability is only exploitable on Windows builds that link against
GDI+ (`Gdiplus.dll`) and compile `io-gdip-utils.c`.

## Expected Behavior on This System

Running `gdk-pixbuf-pixdata vuln_001.gif vuln_001_out.c` will either:
- Exit with an error indicating the format is not recognized/supported, or
- Exit cleanly after ignoring the GIF (pixdata loader rejects non-pixdata input).

No crash, no OOB read, no ASAN report.

## Status

**SKIPPED** — The vulnerable code (`io-gdip-utils.c`) is not compiled into
this Linux build. The PoC GIF is provided for reference and to document the
correct attack structure for Windows/GDI+ targets.
