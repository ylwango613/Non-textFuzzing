After carefully analyzing the complete file in detail, here is my assessment:

**Analysis summary:**

- **Lines 396 & 418 — cursor dimension overflow checks**: The two-step check uses `w*(int64_t)h*c->bpp2 > INT_MAX/2 - 2` (correct int64 cast) followed by `c->cur_w * c->cur_h >= INT_MAX / c->bpp2`. After the first check passes, `cur_w * cur_h <= (INT_MAX/2-2)/bpp2 < INT_MAX`, so the 32-bit multiplication in the second check cannot overflow. `screen_size = cur_w * cur_h * bpp2` is safe.

- **Line 469 — `w * h * c->bpp2` check**: Can theoretically overflow for very large dimensions (bpp2=4, w≈h≈32768), making the check vacuously true. However: (a) `ff_reget_buffer` would fail (ENOMEM) for such frame sizes before reaching this point, causing early return at line 342; (b) even if reached, `paint_raw` writes are bounded within the frame by the coordinate validation at line 386; (c) `bytestream2_get_*` returns 0 safely past end.

- **`screendta` buffer accesses** (lines 369, 510): Index `i * cur_w * bpp2` with `i < h ≤ cur_h`, copy length `w * bpp2` where `w ≤ cur_w`. Maximum end offset = `cur_h * cur_w * bpp2` = allocated size. Within bounds.

- **`decode_hextile()`**: Subrect bounds are validated at line 300; tile dimensions are ≤ 16×16; all bytestream reads have adequate guards.

- **`put_cursor()` and `load_cursor()`**: Correctly use cursor dimensions; clipping logic preserves `w ≤ cur_w` invariant.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
