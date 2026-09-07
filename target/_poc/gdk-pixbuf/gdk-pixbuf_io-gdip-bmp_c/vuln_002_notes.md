# VULN 002 – NULL Pointer Dereference via Unchecked g_try_malloc (io-gdip-utils.c)

## Summary

Three property-retrieval functions in `gdk-pixbuf/io-gdip-utils.c` call
`g_try_malloc(item_size)` without checking whether the return value is NULL
before passing it directly to a GDI+ API:

| Function | Lines |
|---|---|
| `gdip_bitmap_get_property_as_string()` | 409–411 |
| `gdip_bitmap_get_frame_delay()` | 493–495 |
| `gdip_bitmap_get_n_loops()` | 523–524 |

Pattern (same in all three):

```c
item = (PropertyItem *)g_try_malloc(item_size);          // may return NULL
if (Ok == GdipGetPropertyItem(..., item_size, item)) {   // item == NULL → crash
```

`g_try_malloc` is the non-aborting variant of `g_malloc`; it returns NULL on
allocation failure. A missing NULL-check means the NULL pointer is immediately
forwarded to `GdipGetPropertyItem`, which will dereference it.

## Trigger Condition

The vulnerability requires **one of**:

1. A crafted image whose EXIF/GDI+ metadata reports an extremely large
   `item_size` (e.g. close to SIZE_MAX) so that `g_try_malloc(item_size)`
   cannot satisfy the request and returns NULL.
2. System-wide OOM (Out of Memory) at the moment of the `g_try_malloc` call.

In practice, condition 1 is constrained by the GDI+ parser: GDI+ itself
validates the metadata before returning `item_size` via
`GdipGetPropertyItemSize`, so it is non-trivial to make GDI+ report a
legitimately enormous but formally valid size while still having the image
accepted up to that point.

## Why This Cannot Be Triggered on This Linux Build

The `io-gdip-*.c` files implement a loader that wraps **Windows GDI+**
(`GdipGetPropertyItemSize`, `GdipGetPropertyItem`, etc.).
GDI+ is a Windows-only API (part of `gdiplus.dll`).

Inspection of the Linux build confirms:

* `strings gdk-pixbuf-pixdata | grep -i gdip` → **no output** (no GDI+ symbols
  linked into the binary).
* `find build_test/ -name "*gdip*"` → **no files found**.

The loader is therefore **not compiled into this Linux build** and cannot be
exercised at all. The crafted BMP produced by `vuln_002_gen.py` will be handled
by the native BMP loader (`io-bmp.c`), which does not contain the vulnerable
code path.

## Classification

**SKIPPED** – The io-gdip loader is absent from this Linux build. Triggering
the vulnerability requires:
1. A Windows build with GDI+ available, **or** a Linux build using the
   Wine/Mono GDI+ shim, **and**
2. Either a crafted image whose metadata causes GDI+ to report a huge
   `item_size`, or a genuine OOM condition.

Neither condition can be produced with the available binary on this system.

## Recommended Fix

Add a NULL-check after each `g_try_malloc` call, for example:

```c
item = (PropertyItem *)g_try_malloc(item_size);
if (item == NULL)
    return FALSE;
if (Ok == GdipGetPropertyItem(..., item_size, item)) {
    ...
}
```
