# VULN 001 — Win32ErrorHandler / Win32WarningHandler Heap Buffer Overflow

## Status: SKIPPED

## Reason

The vulnerability lives entirely inside `libtiff/libtiff/tif_win32.c`, which is a
**Windows-only** translation unit. Three independent checks all confirm the affected
code is absent from the target binary on this system:

1. **Source-level platform guard** — `tif_win32.c` unconditionally includes
   `<windows.h>` (line 33) and uses Win32 API calls (ReadFile, WriteFile,
   GetLastError, FormatMessage, MessageBox, etc.) throughout. It is compiled only
   when building for the Windows target. No `#ifdef` guards are needed because the
   entire file is platform-specific; the build system selects `tif_unix.c` on
   POSIX/Linux and `tif_win32.c` on Windows.

2. **Binary architecture** — The target binary
   `/data/ylwang/non-textfuzz/target/libtiff/build_test/bin/tiffsplit` is an
   **ELF 64-bit LSB PIE executable for x86-64 GNU/Linux**, not a Windows PE.
   Running on Linux (confirmed by `uname -s`), it was compiled against the POSIX
   back-end, not the Win32 back-end.

3. **Symbol absence** — `nm` on the binary finds **no Win32 symbols**; in
   particular `Win32ErrorHandler` and `Win32WarningHandler` are not present in the
   symbol table.

## Conclusion

`Win32ErrorHandler` and `Win32WarningHandler` cannot be reached by passing any
crafted TIFF file to `tiffsplit` on this Linux system.  Reproducing the
vulnerability would require building libtiff on a Windows host and running the
Windows `tiffsplit.exe`. No PoC is generated.
