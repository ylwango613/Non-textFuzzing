# VULN 002 – NULL Pointer Dereference via Unchecked g_try_malloc in GDI+ Property Functions

## Summary

| Field            | Value |
|------------------|-------|
| ID               | vuln_002 |
| CWE              | CWE-476 (NULL Pointer Dereference) |
| Source file      | gdk-pixbuf/io-gdip-utils.c |
| Affected lines   | 409-410, 493-494, 522-524 |
| Affected functions | `gdip_bitmap_get_property_as_string()`, `gdip_bitmap_get_frame_delay()`, `gdip_bitmap_get_n_loops()` |
| Platform         | Windows (GDI+ required) |
| Status           | SKIPPED – GDI+ loader not present in Linux build |

---

## Vulnerability Description

Three functions in `io-gdip-utils.c` call `g_try_malloc()` to allocate a buffer
whose size is derived directly from the `length` field of a GDI+ property item:

```c
/* gdip_bitmap_get_frame_delay – lines 493-494 */
guchar *buf = g_try_malloc (item->length);
memcpy (buf, item->value, item->length);   /* NULL dereference if alloc fails */

/* gdip_bitmap_get_n_loops – lines 522-524 */
guchar *buf = g_try_malloc (item->length);
memcpy (buf, item->value, item->length);

/* gdip_bitmap_get_property_as_string – lines 409-410 */
buf = (guchar *) g_try_malloc (item->length + 1);
/* buf used without NULL check */
```

`g_try_malloc()` returns `NULL` on allocation failure instead of aborting, but
the code never checks the return value before using the pointer.  An attacker can
cause the allocation to fail by:

1. **Memory exhaustion** – craft an image that first allocates large amounts of
   memory, then request a property read when heap space is nearly gone.
2. **Fraudulently large property size** – provide a malformed GDI+-parseable
   image where the property `length` field is an enormous value (e.g. 0x7FFFFFFF),
   forcing a huge allocation that GDI+ itself may truncate but still report as
   the original size.

---

## Trigger Path

```
crafted animated GIF (or TIFF/WMF)
  → gdk_pixbuf__gdip_image_stop_load()       [io-gdip-wmf.c]
    → stop_load()
      → gdip_bitmap_get_frame_delay()         [io-gdip-utils.c:493]
          g_try_malloc(item->length) → NULL
          memcpy(NULL, ...)                   ← CRASH (SIGSEGV / ASAN: null-deref)
      → gdip_bitmap_get_n_loops()             [io-gdip-utils.c:522]
          g_try_malloc(item->length) → NULL
          memcpy(NULL, ...)                   ← CRASH
```

---

## Why This Cannot Be Triggered on the Linux Test Build

1. **GDI+ is a Windows-only subsystem.**  The Windows GDI+ DLL (gdiplus.dll)
   exposes the `Gdiplus::Bitmap` / `GdipGetPropertyItem` API that these functions
   wrap.  This API does not exist on Linux.

2. **The GDI+ loader module is not compiled in.**  Inspecting the build output
   confirms only `libgdk_pixbuf-2.0.so` is present.  No `libpixbufloader-wmf.so`
   or equivalent module exists:

   ```
   /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/libgdk_pixbuf-2.0.so
   (no wmf / gdip loader .so found)
   ```

3. **`strings` on the binary shows zero GDI+ / WMF references.**

4. **Heap-exhaustion requirement.**  Even on a Windows build, reliably causing
   `g_try_malloc` to return NULL requires actual memory pressure, which is
   difficult to engineer deterministically in a PoC without consuming nearly all
   available virtual memory.

---

## Crafted GIF Structure (vuln_002.gif)

The generated `vuln_002.gif` is a standards-conforming animated GIF89a with
256 frames and a NETSCAPE2.0 loop extension.  On a GDI+ platform, loading this
image causes GDI+ to create a `PropertyTagFrameDelay` item whose `length` is
`4 * 256 = 1024` bytes.  The attack is realised by:

- Replacing the frame count with an extremely large value such that
  `4 * N` overflows or produces a size that cannot be satisfied by `g_try_malloc`.
- Running the loader under memory pressure (e.g. `ulimit -v` or a memory-filling
  child process) so that even a moderate allocation fails.

---

## Recommended Fix

Add a NULL check after every `g_try_malloc` call in `io-gdip-utils.c`:

```c
guchar *buf = g_try_malloc (item->length);
if (buf == NULL) {
    g_set_error (error, GDK_PIXBUF_ERROR, GDK_PIXBUF_ERROR_INSUFFICIENT_MEMORY,
                 "Could not allocate memory for GDI+ property item");
    return default_value;
}
memcpy (buf, item->value, item->length);
```
