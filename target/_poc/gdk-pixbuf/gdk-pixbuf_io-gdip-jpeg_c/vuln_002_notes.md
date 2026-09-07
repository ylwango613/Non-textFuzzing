# VULN 002 — Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay

## Vulnerability Summary

- **File:** io-gdip-utils.c, lines 496–498
- **Function:** `gdip_bitmap_get_frame_delay()`
- **CWE:** CWE-125 (Out-of-bounds Read)
- **Root cause:** Wrong `item_count` calculation leads to reading past the end of a heap-allocated buffer when processing GIF/animated image frame delay metadata.

## Why This Cannot Be Triggered on Linux

### 1. GDI+ is a Windows-only subsystem

`io-gdip-utils.c` and `io-gdip-jpeg.c` are part of the GDI+ (Graphics Device Interface Plus) loader backend for gdk-pixbuf. GDI+ is a Windows API component (`Gdiplus.dll`) and has no equivalent on Linux. The source files contain Windows-specific headers (`<windows.h>`, `<gdiplus.h>`) and are gated behind compile-time checks for Win32/MinGW platforms.

### 2. The gdip loader is not compiled into the Linux build

Verification via symbol inspection:

```
nm /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/libgdk_pixbuf-2.0.so | grep -i gdip
# → no output; no gdip symbols exist in the shared library
```

The meson/autotools build system only includes `io-gdip-*.c` when targeting Windows. On Linux, the GIF format is handled by a separate loader (`io-gif.c`) that does not share the vulnerable code path.

### 3. The loader registry confirms no gdip loader

The compiled loader cache at:
`/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache`

contains no gdip entry. Only statically-compiled loaders are present, and gdip is not among them.

### 4. The target binary only handles pixdata format

The test binary `gdk-pixbuf-pixdata` is a utility that converts between the `.pixdata` inline image format and other formats. It does not invoke any GIF/animated-image loader, and the gdip code path is entirely absent from the process address space.

## Conclusion

The vulnerability in `gdip_bitmap_get_frame_delay()` is unreachable on this Linux build. A PoC can only be developed in a Windows environment where:
- gdk-pixbuf is built with MinGW/MSVC targeting Win32
- The GDI+ loader (`io-gdip-utils.c`) is compiled and linked
- A crafted animated GIF or multi-frame image triggers the frame-delay parsing path

No PoC is generated for this Linux target.
