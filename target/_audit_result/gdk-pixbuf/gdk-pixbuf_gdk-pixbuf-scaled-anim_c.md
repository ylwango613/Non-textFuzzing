After a thorough multi-pass read of `gdk-pixbuf-scaled-anim.c` (281 lines) and cross-referencing all relevant callers and callees:

**Pass 1 — `get_scaled_pixbuf` (lines 118-149):**
Calls `gdk_pixbuf_scale_simple` with dimensions computed as `MAX((int)((gdouble)gdk_pixbuf_get_width(pixbuf) * scaled->xscale + .5), 1)`. The `xscale` is always derived from `priv->width / image_width` (loader.c:337), so the product approximates `priv->width`, an application-controlled `gint`. The `MAX(..., 1)` clamp prevents any negative wrap from reaching allocation. No overflow path reachable from image data.

**Pass 2 — `get_size` (lines 162-173):**
`(int)(*width * scaled->xscale + .5)` — same reasoning: xscale ≈ priv->width/image_width, product ≈ priv->width. No attacker-driven overflow.

**Pass 3 — `get_delay_time` (lines 215-225):**
`delay = (int)(delay * scaled->scaled->tscale)` — tscale is always 1.0 in the only caller (loader.c:339). No overflow.

**Pass 4 — memory management (`finalize`, `get_scaled_pixbuf`):**
`g_object_unref` on `scaled->current` before reassigning is correct. No use-after-free. GObject reference counting is handled cleanly throughout.

**Pass 5 — `gdk_pixbuf_scale_simple` (scale.c:336-337):**
Guards `dest_width > 0` and `dest_height > 0` before any allocation; safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
