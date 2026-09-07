# VULN-001: OFFSET Macro Signed Integer Overflow

**File:** `gdk-pixbuf/gdk-pixbuf-scale.c`, line 399  
**Status:** SKIPPED (not triggerable via gdk-pixbuf-pixdata)

---

## Vulnerability Description

At line 399 of `gdk-pixbuf-scale.c`, a macro is defined:

```c
#define OFFSET(pb, x, y) ((x) * (pb)->n_channels + (y) * (pb)->rowstride)
```

This macro uses **signed integer arithmetic** (all operands are `gint` / `int`). When
`y * rowstride` overflows a signed 32-bit integer, the result is undefined behavior (UB)
and in practice wraps to a negative value, causing the computed offset to be negative.
This leads to a heap out-of-bounds read or write when the offset is used to index into
pixel buffers.

**Trigger condition:**  
- `height` large enough so `(height - 1) * rowstride > INT_MAX` (2147483647)  
- For RGBA (`rowstride = width * 4`), with `width = 1` → `rowstride = 4`  
- Overflow occurs when `(height - 1) * 4 > 2147483647`, i.e., `height > 536870913`  
- At `height = 600000000`: `(600000000 - 1) * 4 = 2399999996 > 2147483647` ✓

**Affected functions:**
- `gdk_pixbuf_rotate_simple()` — uses OFFSET at multiple loop iterations
- `gdk_pixbuf_flip()` — uses OFFSET when copying rows/columns

UBSAN would report: `signed integer overflow: N * 4 cannot be represented in type 'int'`

---

## Why gdk-pixbuf-pixdata Cannot Trigger This

The binary `gdk-pixbuf-pixdata` (source: `gdk-pixbuf/gdk-pixbuf/gdk-pixbuf-pixdata.c`)
performs the following operations only:

1. `gdk_pixbuf_new_from_file()` — load image from file
2. `gdk_pixdata_from_pixbuf()` — convert pixbuf to GdkPixdata (serialization format)
3. Write the pixdata to an output file

Neither `gdk_pixbuf_rotate_simple()` nor `gdk_pixbuf_flip()` are called anywhere in
the pixdata tool's source or call chain. Confirmed by grep over the entire source tree:
no references to `rotate_simple` or `flip` in the pixdata tool source.

Additionally, even if we could get the loader to accept a BMP claiming
`height = 600000000`, gdk-pixbuf would need to allocate approximately
`1 * 600000000 * 4 = 2.4 GB` of memory for the pixel buffer. This allocation would
likely fail on most systems, and the loader would return `NULL` before the vulnerable
code path is reached.

---

## Real Trigger Path (in a complete application)

To trigger VULN-001 in a real application:

1. **Load** a pixbuf from a file that the loader accepts with large dimensions.
   (In practice, the dimension may need to be smaller but still cause overflow, 
   e.g., height = 600000000 is likely too large to allocate; finding a boundary where
   allocation succeeds but `y * rowstride` still overflows requires tuning.)

2. **Call** one of:
   - `gdk_pixbuf_rotate_simple(pixbuf, GDK_PIXBUF_ROTATE_CLOCKWISE)` (or any non-zero angle)
   - `gdk_pixbuf_flip(pixbuf, TRUE/FALSE)`

3. Inside the function, the loop at high `y` values computes:
   ```c
   p = src_pixels + OFFSET(src, x, y);
   ```
   When `y` is large enough, `y * rowstride` wraps negative, making the offset
   point before the start of `src_pixels` → heap OOB access.

**Example vulnerable call (hypothetical application):**
```c
GdkPixbuf *src = gdk_pixbuf_new_from_file("trigger.bmp", NULL);
if (src) {
    GdkPixbuf *rotated = gdk_pixbuf_rotate_simple(src, GDK_PIXBUF_ROTATE_CLOCKWISE);
    // ^ crashes here due to OFFSET overflow
}
```

---

## Memory Requirements

- To allocate a pixbuf of height H, width W, 4 channels: `W * H * 4` bytes needed
- For the overflow to trigger: `(H - 1) * rowstride > INT_MAX`
  - With `rowstride = W * 4` (typical): `H > INT_MAX / (W * 4) + 1`
  - Minimum H at W=1: `H > 536870913` → requires at minimum ~2.15 GB allocation
  - At W=2: `H > 268435457` → ~2.15 GB still
- In practice, systems with < 4 GB available memory will fail the allocation before
  the vulnerable code is reached, making exploitation memory-constrained.

---

## EXIF/Auto-rotation Consideration

Some loaders (e.g., JPEG via libjpeg-turbo, TIFF) may apply EXIF-based auto-rotation
via `gdk_pixbuf_apply_embedded_orientation()`. However:
- This function calls `gdk_pixbuf_rotate_simple()` internally if the EXIF orientation tag
  indicates rotation.
- BMP format does not support EXIF metadata, so BMP-loaded images will not trigger
  auto-rotation.
- A JPEG with EXIF orientation set to 90°/270° and crafted extreme dimensions could
  potentially reach `gdk_pixbuf_rotate_simple()` automatically during load.
- However, the `gdk-pixbuf-pixdata` tool does not call `apply_embedded_orientation()`
  either, so this path is also not available via the target binary.

---

## Conclusion

**SKIPPED:** The vulnerability exists in the library source code at
`gdk-pixbuf-scale.c:399` and is reachable only via `gdk_pixbuf_rotate_simple()` or
`gdk_pixbuf_flip()`. The `gdk-pixbuf-pixdata` binary does not exercise these code paths.
A real PoC would require a custom application (not a compiled-from-scratch binary)
that calls these functions, or a loader that auto-applies orientation transforms.
