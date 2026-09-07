# VULN 001 - SKIPPED

## Vulnerability

**VULN 001: Heap Buffer Overflow via Integer Overflow in ppm2tiff linebytes Calculation**

- File: `libtiff/tools/ppm2tiff.c`, lines 228-243
- Tool: `ppm2tiff`
- Input format: PPM file (P6/RGB format)
- Trigger condition: crafted PPM with w in [1431655767, 2147483647], spp=3

## Reason for Skipping

This vulnerability **cannot be triggered** under the constraint that the only allowed binary is `tiffsplit`. The reasons are:

1. **Wrong binary**: The vulnerability resides in `ppm2tiff.c`'s `main()` function. It is only reachable when the `ppm2tiff` binary is executed. The only allowed binary in this evaluation is `tiffsplit`, which is a completely separate tool.

2. **Wrong input format**: `ppm2tiff` reads PPM image files (Portable Pixmap format, magic `P6`/`P3`) as its input and converts them to TIFF. `tiffsplit` reads TIFF files as input and splits them into multiple single-image TIFF files. There is no code path by which a TIFF file passed to `tiffsplit` can reach the `ppm2tiff` parsing or `linebytes` calculation logic.

3. **No shared code path**: The integer overflow in `linebytes` at lines 228-243 of `ppm2tiff.c` is specific to `ppm2tiff`'s internal PPM header parsing and buffer allocation. This code is not linked into or called by `tiffsplit`.

4. **Conclusion**: Since the vulnerability code path in `ppm2tiff.c` is unreachable via `tiffsplit` with any crafted TIFF input, no PoC can be generated for this vulnerability under the given constraints. The vulnerability is skipped.
