# vuln_001 — SKIPPED

## Vulnerability

- **File:** `libtiff/tif_win3.c`
- **Functions:** `win3ErrorHandler()` (lines 202–212), `win3WarningHandler()` (lines 215–224)
- **Type:** Stack Buffer Overflow (CWE-121)

## Why SKIPPED

`tif_win3.c` is a **Windows 3.x-specific** platform source file. On Linux, the build
system selects `tif_unix.c` instead, which provides `unixErrorHandler` and
`unixWarningHandler`. The Windows 3.x handlers are never compiled into the Linux binary.

### Evidence

1. **`nm` on the tiffsplit binary** — no `win3ErrorHandler` or `win3WarningHandler`
   symbols are present; no `win3` string appears anywhere in the symbol table.

2. **`nm` on `libtiff/build_test/lib/libtiff.so`** — only `unixErrorHandler` and
   `unixWarningHandler` exist as error/warning handler implementations; the win3
   variants are absent.

3. **`objdump` / `strings`** — no reference to `win3` appears in the compiled binary.

4. **Build system (`libtiff/CMakeLists.txt`)** — `tif_win3.c` is listed only in the
   legacy `Makefile.am`; the CMake build (used to produce the test binary) does not
   include it for Linux targets.

5. **Source file header** — `tif_win3.c` line 28: `"TIFF Library Windows 3.x-specific
   Routines."` — explicitly a Windows-only compilation unit.

## Conclusion

Because the vulnerable code is never compiled or linked into the Linux `tiffsplit`
binary, the overflow in `win3ErrorHandler`/`win3WarningHandler` cannot be triggered
through the command-line interface on this platform. No PoC (`_gen.py`, `_run.sh`,
`_result.txt`) is generated.
