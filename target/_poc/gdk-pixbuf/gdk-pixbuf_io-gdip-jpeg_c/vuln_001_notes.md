# VULN 001: NULL Pointer Dereference via Unchecked g_try_malloc — Not Triggerable on Linux

## Vulnerability Summary

- **File**: io-gdip-utils.c (lines 410, 494, 523)
- **Functions**: `gdip_bitmap_get_property_as_string()`, `gdip_bitmap_get_frame_delay()`, `gdip_bitmap_get_n_loops()`
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **Claimed vector**: crafted JPEG/GIF image with oversized EXIF/property metadata

## Why This Vulnerability Cannot Be Triggered on Linux

### 1. GDI+ is a Windows-only subsystem

The source files `io-gdip-jpeg.c` and `io-gdip-utils.c` implement a gdk-pixbuf image loader that wraps the Windows GDI+ imaging library (`Gdiplus`). GDI+ is part of the Win32 API and ships only on Windows (XP and later). It has no native equivalent on Linux, and no stable cross-platform port is used by the gdk-pixbuf project.

### 2. The gdip loader is not compiled into the Linux build

Inspection of the compiled shared library confirms no gdip symbols are present:

```
nm /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/libgdk_pixbuf-2.0.so | grep -i gdip
# (no output — zero gdip symbols)
```

Functions such as `gdip_bitmap_get_property_as_string`, `gdip_bitmap_get_frame_delay`, and `gdip_bitmap_get_n_loops` do not exist in the binary.

### 3. The loaders.cache confirms only the pixdata loader is compiled in

```
cat /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache
# GdkPixbuf Image Loader Modules file
# dynamic loading of modules not supported
# (no loaders listed — only static pixdata loader is built in)
```

The build uses static loader registration. Only the pixdata loader is present; no JPEG, GIF, or gdip loader is registered or loadable.

### 4. The target binary cannot reach the vulnerable code

The target binary `/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata` operates exclusively on `.pixdata` format files via the pixdata loader. There is no code path from this binary to `io-gdip-utils.c` on any platform.

Even if the binary were rebuilt on Windows with GDI+ available, the vulnerable functions would only be reachable via the gdip JPEG/GIF loader — a separate loader module that is not present in this build.

## Conclusion

VULN 001 describes a real vulnerability class in Windows-specific source code. It cannot be triggered via the Linux `gdk-pixbuf-pixdata` binary because:

- The gdip loader is conditionally compiled for Windows only.
- No gdip symbols exist in the Linux shared library.
- The loaders.cache confirms no JPEG/GIF loader is registered.
- The pixdata binary has no code path to the vulnerable functions.

**Status: SKIPPED** — not applicable to the Linux target.
