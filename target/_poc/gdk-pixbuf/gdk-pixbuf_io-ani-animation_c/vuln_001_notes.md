# VULN 001 — Integer Overflow in ANI iter->elapsed: SKIPPED

## Vulnerability Summary

File: `gdk-pixbuf/gdk-pixbuf/io-ani-animation.c`

In `gdk_pixbuf_ani_anim_iter_advance()` (line 191), the field `iter->elapsed`
accumulates per-frame delay values in a `gint` (32-bit signed). If a crafted ANI
file sets per-frame delays large enough that their sum exceeds `INT_MAX`, `elapsed`
overflows to a negative value. The loop (lines 228-233) then runs past `n_frames`,
setting `current_frame = n_frames`. Subsequent accesses to `delay[current_frame]`
(line 249) and `sequence[current_frame]` / `pixbufs[frame]` (lines 260-266) are
out-of-bounds reads relative to the allocated arrays.

Trigger condition:
- ANI file with NumFrames/NumSteps >= 31 and per-step rate = 0xFFFFFFFF
  (gives delay_ms ≈ 71582771; 31 × 71582771 = 2219065901 > INT_MAX)
- Call path: load ANI file → get_iter → advance(iter, time)

## Why This Binary Cannot Trigger the Vulnerability

Binary source: `gdk-pixbuf/gdk-pixbuf/gdk-pixbuf-pixdata.c` (line 77)

```c
pixbuf = gdk_pixbuf_new_from_file(infilename, &error);
```

### Actual call path for ANI files

`gdk_pixbuf_new_from_file` calls `_gdk_pixbuf_generic_image_load` (gdk-pixbuf-io.c:1021).

The ANI module (`io-ani.c`, fill_vtable at line 645) only registers:
```c
module->begin_load     = gdk_pixbuf__ani_image_begin_load;
module->stop_load      = gdk_pixbuf__ani_image_stop_load;
module->load_increment = gdk_pixbuf__ani_image_load_increment;
```
It does NOT register `module->load` or `module->load_animation`.

Because `module->begin_load != NULL`, `_gdk_pixbuf_generic_image_load` takes the
`generic_load_incrementally` branch (gdk-pixbuf-io.c:1028). That function:
1. Calls `begin_load(NULL, prepared_notify, NULL, &pixbuf, error)` where
   `prepared_notify` (gdk-pixbuf-io.c:972) simply stores the first pixbuf received.
2. Feeds the file data through `load_increment` in chunks.
3. Calls `stop_load` and returns the stored pixbuf.

No animation iteration occurs. The `GdkPixbufAniAnim` object is created internally
by the loader, but the only pixbuf extracted is frame 0 via the `prepared_func`
callback, which is fired by `prepared_callback` in io-ani.c (line 163) when the
first ICO image is ready. Neither `gdk_pixbuf_animation_get_iter()` nor
`gdk_pixbuf_animation_iter_advance()` is ever called.

### What would be needed to trigger the vulnerability

A program would need to:
```c
GdkPixbufAnimation *anim = gdk_pixbuf_animation_new_from_file(path, NULL);
GTimeVal now;
g_get_current_time(&now);
GdkPixbufAnimationIter *iter = gdk_pixbuf_animation_get_iter(anim, &now);
// Advance to a time far in the future to exercise many frames:
GTimeVal future = { now.tv_sec + 10000, now.tv_usec };
gdk_pixbuf_animation_iter_advance(iter, &future);
// Now iter->current_frame may be OOB
gdk_pixbuf_animation_iter_get_pixbuf(iter);  // OOB read
```

No such code exists in `gdk-pixbuf-pixdata.c`.

## Status

**SKIPPED** — the vulnerable code path is not reachable from the `gdk-pixbuf-pixdata`
binary. A different test harness that explicitly drives animation playback (e.g., a
GTK application rendering an animated cursor) would be needed to exercise this bug.
