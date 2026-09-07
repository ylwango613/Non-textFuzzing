Now I have a complete picture. Let me trace all code paths reachable from `io-gdip-emf.c`.

**EMF code path analysis:**

1. `io-gdip-emf.c:fill_vtable` → `gdip_fill_vector_vtable` → registers `gdk_pixbuf__gdip_image_stop_vector_load` as `stop_load`
2. `gdk_pixbuf__gdip_image_stop_vector_load` → `gdip_buffer_to_image` (loads EMF as GpImage metafile) → `GdipCreateBitmapFromScan0(width, height, ...)` → `GdipDrawImageI` (renders metafile to raster bitmap) → `stop_load(bitmap, ...)`
3. `stop_load` → `gdip_bitmap_get_n_frames(bitmap, &n_frames, TRUE)` → `gdip_bitmap_get_frame_delay` for each frame → `gdip_bitmap_to_pixbuf`

**Key findings during analysis:**

**`gdip_bitmap_get_frame_delay` (io-gdip-utils.c:496)**: `item_count = item_size / sizeof(long)` is incorrect — `item_size` includes the `PropertyItem` header overhead (16 bytes on 32-bit / 24 bytes on 64-bit Windows LLP64), so `item_count` is overestimated by 4–6 entries vs `item->length / sizeof(long)`. If `frame >= actual_count` but `< item_count`, the access `((long*)item->value)[frame]` reads 12–24 bytes past the end of the heap allocation. This **is a real OOB heap read**, but—

**Critical reachability check for EMF**: The bitmap in the EMF path is created fresh via `GdipCreateBitmapFromScan0` (a blank raster target). This bitmap has:
- Exactly **1 frame** (not animated) — so the loop runs once with `frame=0`
- **No PropertyTagFrameDelay property** — `GdipGetPropertyItemSize` returns `PropertyNotFound`, the inner `if` block is skipped entirely, `*delay` stays 0

The OOB is therefore **not reachable** via a crafted EMF file through this code path.

**Dimension overflow** (`gdk_pixbuf__gdip_image_stop_vector_load:775-778`): Attacker-controlled `width`/`height` from EMF header feed into `GdipCreateBitmapFromScan0(width, height, ...)` and later `gdk_pixbuf_new`. Both APIs return failures on extreme values, and both failure paths are checked and handled correctly.

**`g_try_malloc` without NULL check** (io-gdip-utils.c:494, 523, 410): True DoS potential under OOM, but not reachable via the EMF path due to the property-not-found early exit above.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
