# VULN-002: NULL Pointer Dereference via g_try_malloc Unchecked Return in Property Item Functions

## Summary

**Status: SKIPPED — Windows-only vulnerability, GDI+ loader not present on this Linux build.**

## Vulnerability Details

- **Title:** NULL Pointer Dereference via `g_try_malloc` Unchecked Return in Property Item Functions
- **File:** `gdk-pixbuf/io-gdip-utils.c`
- **Lines:** 409-410, 493-494, 521-523
- **Functions:**
  - `gdip_bitmap_get_property_as_string()` (line 410)
  - `gdip_bitmap_get_frame_delay()` (line 494)
  - `gdip_bitmap_get_n_loops()` (line 523)

## Root Cause

In all three functions, the pattern is identical:

```c
item = (PropertyItem *)g_try_malloc(item_size);
if (Ok == GdipGetPropertyItem((GpImage *)bitmap, propertyId, item_size, item)) {
    // uses item->value, item->type, item->length ...
}
```

`g_try_malloc()` is the non-aborting variant of `g_malloc()` — it returns `NULL` on allocation
failure instead of calling `g_error()`. However, the return value is **never checked** before
being passed as the write buffer to `GdipGetPropertyItem()`. When `g_try_malloc()` returns `NULL`
(OOM or oversized allocation), `GdipGetPropertyItem()` will attempt to write the property item
data into address `0x0`, causing a NULL pointer dereference / write-to-null crash.

In `gdip_bitmap_get_property_as_string()` (line 411), the code additionally accesses
`item->type`, `item->length`, and `item->value` after the NULL-checked `GdipGetPropertyItem`
call — but the `GdipGetPropertyItem` itself is the primary trigger (it receives `NULL` as the
write target).

## Trigger Conditions

The vulnerability requires:
1. **GDI+ library available** (`gdiplus.dll` on Windows, or a compatible stub).
2. A crafted ICO or animated GIF file is parsed by the GDI+ loader.
3. `GdipGetPropertyItemSize()` reports a very large `item_size` value.
4. `g_try_malloc(item_size)` returns `NULL` (OOM or `item_size` near `SIZE_MAX`/`G_MAXSIZE`).
5. `GdipGetPropertyItem(..., item_size, NULL)` writes to address 0 → crash.

## Why Not Triggerable on This Linux Build

This vulnerability exists **exclusively** in the Windows-specific GDI+ loader:
- Source files: `io-gdip-ico.c`, `io-gdip-gif.c`, `io-gdip-utils.c`
- These files depend on GDI+ (`gdiplus.dll` / `GdipGetPropertyItem`, `GdipGetPropertyItemSize`)
- On Linux, gdk-pixbuf uses **native loaders** (`io-ico.c`, `io-gif.c`) that do not call any
  `GdipGetPropertyItem` functions.

**Verification on this build:**
- `nm libgdk_pixbuf-2.0.so.0.3100.1 | grep -i "gdip_bitmap"` → **no results**
- `strings gdk-pixbuf-pixdata | grep -i "gdip\|gdiplus"` → **no results**
- `loaders.cache` shows no registered loader modules (static build, no GDI+ loaders)

The functions `gdip_bitmap_get_frame_delay()`, `gdip_bitmap_get_n_loops()`, and
`gdip_bitmap_get_property_as_string()` are simply **not compiled** into this binary.

## Fix (for Windows GDI+ builds)

Each allocation site should check the return value before use:

```c
item = (PropertyItem *)g_try_malloc(item_size);
if (item == NULL)
    return FALSE;  /* or handle gracefully */
if (Ok == GdipGetPropertyItem((GpImage *)bitmap, propertyId, item_size, item)) {
    /* safe to use item->... */
}
```

Alternatively, replace `g_try_malloc` with `g_malloc` (which aborts on OOM via `g_error`) if
OOM is not expected to be a recoverable condition in this context.

## Affected Platforms

- **Windows** (GDI+ build): Vulnerable
- **Linux / macOS** (native loader build): Not affected (code path not compiled)
