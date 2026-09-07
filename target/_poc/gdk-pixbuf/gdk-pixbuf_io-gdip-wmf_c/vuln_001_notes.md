# VULN_001: Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay

## Summary

- **ID**: vuln_001
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Source**: `gdk-pixbuf/gdk-pixbuf/io-gdip-utils.c`, lines 490–505
- **Trigger path**: crafted animated GIF/TIFF → `gdk_pixbuf__gdip_image_load_increment` → `gdk_pixbuf__gdip_image_stop_load` → `stop_load` → `gdip_bitmap_get_frame_delay`
- **Status**: SKIPPED — GDI+ loader not available in this Linux build

---

## Vulnerability Detail

In `gdip_bitmap_get_frame_delay()` at `io-gdip-utils.c:496`:

```c
item_count = item_size / sizeof(long);
```

`item_size` is the **total allocation size** returned by `GdipGetPropertyItemSize`, which includes the `PropertyItem` struct header (id: 4 bytes, length: 4 bytes, type: 2 bytes, padding: 2 bytes = 12 bytes) **plus** the payload (`item->length` bytes).

The correct formula should divide only the payload length:

```c
item_count = item->length / sizeof(long);
```

On line 498, the inflated `item_count` causes an OOB read:

```c
*delay = ((long *)item->value)[(frame < item_count) ? frame : item_count - 1];
```

Because `item->value` points only `item->length` bytes of valid data, an attacker can make `frame >= actual_count` but `< inflated_count`, causing `item->value[inflated_count - 1]` to read past the end of the allocated buffer.

### Example

- `item->length` = 4 bytes (1 delay entry of 4 bytes each)
- `item_size` = 16 bytes (12-byte header + 4 bytes payload)
- On 32-bit: `item_count = 16 / 4 = 4` (correct: `4 / 4 = 1`)
- On 64-bit: `item_count = 16 / 8 = 2` (correct: `4 / 8 = 0`, clamped to 1)
- Accessing `frame = 1` on 32-bit reads 4 bytes past the valid region

---

## Why This Cannot Be Triggered on This Linux Build

The vulnerability lives inside `io-gdip-wmf.c` / `io-gdip-utils.c`, which implements a **Windows GDI+ loader**. The GDI+ API (`GdipGetPropertyItemSize`, `GdipGetPropertyItem`, etc.) is a Windows-only API (part of GDI+/gdiplus.dll).

Verification performed:

1. **loaders.cache** at `build_test/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache` is empty — no dynamic loader modules are registered.
2. **No WMF/GDI+ shared objects** found under `build_test/lib/` or elsewhere in the build tree.
3. **strings on binary/library** show no `wmf`, `gdip`, or `gdiplus` strings.
4. `nm` on `libgdk_pixbuf-2.0.so` shows no `gdip` or `wmf` symbols.
5. The Meson/CMake build system for gdk-pixbuf gates the GDI+ loader behind `#ifdef _WIN32` / `INCLUDE_gdiplus`.

Therefore, even a perfectly crafted animated GIF submitted to `gdk-pixbuf-pixdata` on this Linux host will be handled only by the built-in GIF loader (libgif / bundled), not by the GDI+ path, and `gdip_bitmap_get_frame_delay` will never execute.

---

## What Would Be Required to Trigger It

On a Windows build with GDI+ enabled:

1. An animated GIF image recognized by GDI+ as multi-frame.
2. The GIF must have a `PropertyTagFrameDelay` (EXIF tag 0x5100) property item where:
   - `item->length` (payload bytes) is small (e.g. 4 bytes = one `long` slot)
   - `item_size` (struct header + payload) is larger
3. The image must have more frames than `item->length / sizeof(long)` so that the `frame` index falls outside the valid range but inside the inflated `item_count`.
4. Feed the file to a GDI+-enabled gdk-pixbuf build.

---

## Files Generated

- `vuln_001_gen.py` — Creates a structurally valid minimal animated GIF (two frames) as a reference artifact. Cannot trigger the bug on Linux.
- `vuln_001_run.sh` — Runs `gdk-pixbuf-pixdata` against the generated GIF with ASAN.
- `vuln_001_result.txt` — Captured output from the run.
- `vuln_001_status.txt` — Final status: SKIPPED.
