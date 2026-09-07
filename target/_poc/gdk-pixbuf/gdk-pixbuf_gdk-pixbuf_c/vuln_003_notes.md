# VULN 003 - Integer Overflow in gdk_pixbuf_new_from_bytes Size Validation

## Vulnerability Summary

**Location**: `gdk-pixbuf/gdk-pixbuf/gdk-pixbuf-data.c`, line 113  
**Function**: `gdk_pixbuf_new_from_bytes()`

The vulnerable size check:
```c
g_return_val_if_fail(g_bytes_get_size(data) >= width * height * (has_alpha ? 4 : 3), NULL);
```
uses signed `int` arithmetic for the right-hand side multiplication. With `width=32768`,
`height=32768`, `has_alpha=TRUE`: `32768 × 32768 × 4 = 4294967296`, which overflows a
32-bit signed integer and wraps to `0`. This makes `g_bytes_get_size(data) >= 0` always
true, allowing creation of a GdkPixbuf object backed by far too little pixel data.

## Analysis: Can This Be Triggered via `gdk-pixbuf-pixdata`?

**Verdict: NO — this vulnerability CANNOT be triggered via image file input.**

### Evidence

1. **No image loader calls `gdk_pixbuf_new_from_bytes()`**

   A grep of all image loader source files (`io-*.c`) in
   `/data/ylwang/non-textfuzz/target/gdk-pixbuf/gdk-pixbuf/` found **zero** calls to
   `gdk_pixbuf_new_from_bytes`. The loaders confirmed to NOT use this API include:
   - `io-bmp.c`, `io-png.c`, `io-gif.c`, `io-ico.c`, `io-jpeg.c`, `io-tiff.c`,
     `io-pnm.c`, `io-xpm.c`, `io-pixdata.c`, and all others.

2. **`gdk-pixbuf-pixdata` binary uses `gdk_pixbuf_new_from_file()`, not `gdk_pixbuf_new_from_bytes()`**

   The binary's `main()` function (gdk-pixbuf-pixdata.c, line 77):
   ```c
   pixbuf = gdk_pixbuf_new_from_file(infilename, &error);
   ```
   It loads the input image via the standard file-based loader chain, which calls the
   format-specific `io-*.c` loaders. None of those loaders call `gdk_pixbuf_new_from_bytes`.
   The binary then converts the loaded pixbuf to pixdata format and writes it out. There is
   no code path from image file input to `gdk_pixbuf_new_from_bytes`.

3. **`gdk_pixbuf_new_from_bytes()` is a public API function only**

   It appears only in:
   - `gdk-pixbuf-data.c` — the implementation
   - `gdk-pixbuf-core.h` — the declaration
   - `tests/pixbuf-readonly-to-mutable.c` — a unit test that calls it directly
   - Symbol export files (`.exp`, `.ver`, `.def`, `.symbols`) and documentation/GIR files

   There is no loader or internal gdk-pixbuf code that routes file-based loading through
   this function.

### Root Cause of Non-Triggerability

`gdk_pixbuf_new_from_bytes()` is designed for callers who already have raw pixel data in
memory (e.g., from a GPU readback, a network buffer, or a pre-processed array) and want
to wrap it in a GdkPixbuf without copying. The API takes caller-supplied `width`, `height`,
and a `GBytes *` of raw pixel data. There is no mechanism by which an attacker can inject
crafted `width`/`height` values of 32768×32768 into this function through a malicious image
file, because no file loader routes through this function.

To exploit this vulnerability, an attacker would need either:
- Direct C/Python/GObject-Introspection code that calls `gdk_pixbuf_new_from_bytes()` with
  crafted parameters, OR
- A higher-level application that exposes this API in a way that accepts externally-supplied
  width/height values.

Neither path is available through `gdk-pixbuf-pixdata` or any standard image file format.

## Conclusion

**Status: SKIPPED**

The vulnerability in `gdk_pixbuf_new_from_bytes()` cannot be triggered by supplying a
crafted image file to `gdk-pixbuf-pixdata` or any other standard gdk-pixbuf command-line
tool. The vulnerable function is a public library API that requires direct programmatic
invocation with specific large integer parameters. No image format loader in the gdk-pixbuf
source calls this function.
