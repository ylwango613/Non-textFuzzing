# VULN 001 - Heap OOB Read in gdip_bitmap_get_frame_delay via Wrong item_count Calculation

## Status: SKIPPED

## Vulnerability Description

- **File:** `gdk-pixbuf/gdk-pixbuf/io-gdip-utils.c`, lines 493-497
- **Function:** `gdip_bitmap_get_frame_delay()`
- **Type:** Heap Out-of-Bounds Read
- **Affected formats:** Animated ICO / GIF (via Windows GDI+ loader)

## Root Cause

In `gdip_bitmap_get_frame_delay()`, the code calculates `item_count` incorrectly:

```c
item_count = item_size / sizeof(long);
*delay = ((long *)item->value)[(frame < item_count) ? frame : item_count - 1];
```

`item_size` is the value returned by `GdipGetPropertyItemSize()`, which is the total
allocation size needed for a `PropertyItem` struct **plus** its embedded data buffer.
The actual number of delay entries in the data is:

```
actual_count = item->length / sizeof(long)
```

But the code uses `item_size / sizeof(long)`, which is:

```
item_count = (sizeof(PropertyItem) + item->length) / sizeof(long)
```

Since `sizeof(PropertyItem)` > 0, `item_count` is always larger than
`actual_count`. This means when a frame index `frame` satisfies:

```
actual_count <= frame < item_count
```

the bounds check `(frame < item_count)` passes, and the code executes:

```c
((long *)item->value)[frame]
```

where `item->value` points to the delay array (length: `item->length` bytes).
Accessing index `frame >= actual_count` reads beyond the delay data into
adjacent heap memory => **heap OOB read**.

## Trigger Condition

1. An animated ICO or GIF file with N frames.
2. The `PropertyTagFrameDelay` EXIF property is embedded with fewer than N
   delay entries (M entries, where M < N).
3. When `gdip_bitmap_get_frame_delay()` is called for a frame index F where
   `M <= F < M + sizeof(PropertyItem)/sizeof(long)`, the OOB read is triggered.

## Why This PoC is SKIPPED on This System

The `io-gdip-ico.c` and `io-gdip-utils.c` loaders depend entirely on the
**Windows GDI+ API** (`GdipGetPropertyItemSize`, `GdipGetPropertyItem`,
`GdipGetFrameCount`, etc.). These APIs are part of the Windows `gdiplus.dll`
and are **not available on Linux**.

### Evidence collected:

1. **No GDI+ symbols in compiled library:**
   ```
   nm /data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/libgdk_pixbuf-2.0.so \
     | grep -i gdip
   # (no output - no GDI+ functions compiled in)
   ```

2. **No GDI+ strings in the shared library:**
   ```
   strings .../libgdk_pixbuf-2.0.so | grep -i "gdip\|PropertyTag\|FrameDelay"
   # (no output)
   ```

3. **Loaders cache is empty:**
   The file `/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache`
   contains only the header comment and "dynamic loading of modules not supported"
   with no loader modules listed.

4. **Source-level guard:** The `io-gdip-ico.c` source uses `#ifndef INCLUDE_gdiplus`
   to switch between dynamic module export and static inclusion. When GDI+ is not
   available (Linux), the build system omits this loader entirely.

5. **Linux uses native ICO loader:** On Linux, `io-ico.c` handles ICO files natively
   without GDI+, so this code path is never reached.

## Exploitability (Windows)

On a Windows build with GDI+ enabled:
- Impact: **Information disclosure** (heap memory leak via OOB read)
- Severity: **Medium** (requires crafted ICO/GIF file, read-only, no write primitive)
- ASAN would report: `READ of size 4` beyond the delay array allocation

## References

- Source: `/data/ylwang/non-textfuzz/target/gdk-pixbuf/gdk-pixbuf/io-gdip-utils.c:480-506`
- Source: `/data/ylwang/non-textfuzz/target/gdk-pixbuf/gdk-pixbuf/io-gdip-ico.c`
