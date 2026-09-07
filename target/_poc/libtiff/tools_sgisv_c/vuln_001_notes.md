# VULN-001 Skip Notes

## Vulnerability
Integer Overflow in ABS() Bypasses Bounds Check → Heap Buffer Overflow in tiffsv()
File: libtiff/tools/sgisv.c, Lines 268-298

## Skip Reason

This vulnerability cannot be triggered by passing a crafted TIFF file to the available `tiffsplit` binary. The following reasons apply:

1. **Wrong binary**: The vulnerability resides in `sgisv.c`, which compiles to the `sgisv` binary — an SGI IRIX screen-capture/save tool. The only available test binary in this environment is `tiffsplit`, which is a completely different tool with a different purpose (splitting multi-page TIFF files into individual files).

2. **Command-line integer arguments, not TIFF file input**: The vulnerability is triggered by passing specific integer coordinate arguments on the command line (`x1=INT_MIN`, `x2=0`, `y1=0`, `y2=1`) to the `sgisv` binary. There is no TIFF file involved in the attack vector; a crafted TIFF file passed to `tiffsplit` would not reach the vulnerable code path in `sgisv.c`.

3. **SGI IRIX-specific graphics API**: The actual heap buffer overflow occurs inside `readdisplay()`, which is an SGI IRIX-specific graphics API call. This API is not present on Linux systems. Even if the `sgisv` binary were compiled and available, `readdisplay()` would not exist, making the overflow impossible to reach on a standard Linux host.

4. **No code path from tiffsplit to sgisv**: `tiffsplit` and `sgisv` are independent executables. There is no call chain or shared library path that would cause a TIFF file processed by `tiffsplit` to invoke the vulnerable `tiffsv()` function in `sgisv.c`.

## Conclusion

All conditions for the SKIP rule are met:
- The required binary (`sgisv`) is not available.
- The vulnerability requires a platform-specific API (`readdisplay()`) unavailable on Linux.
- The attack vector is command-line integer arguments, not a crafted TIFF file.
- The only permitted binary (`tiffsplit`) cannot trigger this vulnerability under any input.
