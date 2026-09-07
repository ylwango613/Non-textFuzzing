# VULN-001: Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay

## Vulnerability Summary

- **File**: `gdk-pixbuf/io-gdip-utils.c` (called from `io-gdip-tiff.c`)
- **Lines**: 494-498
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Function**: `gdip_bitmap_get_frame_delay()`

## Root Cause

At line 496, `item_count` is computed as:

```c
item_count = item_size / sizeof(long);
```

However, `item_size` is the total size returned by `GdipGetPropertyItemSize()`, which includes the `sizeof(PropertyItem)` header (the struct itself) plus the actual delay data. Dividing the full allocation size by `sizeof(long)` yields an `item_count` that is larger than the actual number of delay entries stored in `item->value`.

The subsequent read at line 498:

```c
*delay = ((long *)item->value)[(frame < item_count) ? frame : item_count - 1];
```

...uses `item->value` as the base pointer, which points only to the value portion (past the PropertyItem header). The inflated `item_count` causes this expression to index beyond the allocated buffer when `frame` is chosen to be at or near `item_count - 1`.

## Why This Cannot Be Triggered via gdk-pixbuf-pixdata

### 1. The binary is a pixdata converter, not a general image loader

`gdk-pixbuf-pixdata` (binary at `build_test/bin/gdk-pixbuf-pixdata`) has a single
purpose: convert an image file to GdkPixdata format (embedded C data). Its internal
call chain is:

```
gdk-pixbuf-pixdata [input] [output.c]
  -> gdk_pixbuf_new_from_file()
  -> gdk_pixdata_from_pixbuf()
  -> gdk_pixdata_serialize()
```

It does NOT invoke the GDI+ TIFF loading path
(`gdk_pixbuf__gdip_image_stop_load` → `gdip_buffer_to_bitmap` →
`gdip_bitmap_get_frame_delay`).

### 2. The GDI+ backend is Windows-only

The source files `io-gdip-tiff.c` and `io-gdip-utils.c` implement a
**Win32 GDI+ Pixbuf Loader** (comment at top of `io-gdip-tiff.c`). The
underlying API calls (`GdipGetPropertyItemSize`, `GdipGetPropertyItem`, etc.)
are Windows GDI+ functions that do not exist on Linux.

Evidence from the build:
- No `*gdip*` shared object was found in `build_test/` or its subdirectories.
- `nm -D libgdk_pixbuf-2.0.so.0` returns no `GdipGet*` or `gdip_bitmap*` symbols.
- The loaders cache (`build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache`) contains
  no GDI+ loader entries.
- The binary is linked against `libjpeg.so.8` and `libpng16.so.16` only — no
  Windows GDI+ DLL.

### 3. Module is not statically compiled in either

The loaders cache states: `# dynamic loading of modules not supported`
and lists no loaders at all, confirming all active loaders are baked into
`libgdk_pixbuf-2.0.so.0` statically. The GDI+ module is absent from that set.

## Conclusion

The vulnerable code path exists only in the Windows-specific GDI+ backend, which
is neither compiled for Linux nor reachable through `gdk-pixbuf-pixdata`. A
reproduction on Linux would require a Windows build of gdk-pixbuf with the GDI+
backend compiled in, which is outside the scope of the available test binary.

## Status: SKIPPED
