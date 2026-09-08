After fully reading `ansi.c` (494 lines) and tracing every call chain, I verified the following:

- **Cursor bounds**: all positions (`s->x`, `s->y`) are consistently clamped with `av_clip`/`FFMAX`/`FFMIN` before any frame-buffer offset computation; the clamp at lines 351–352 fires after every `execute_code` call and `hscroll`/`draw_char` also enforce their own local checks.
- **`args[]` indexing**: `s->nb_args` can reach at most `MAX_NB_ARGS` (4) via the digit/semicolon/default handlers; all reads of `s->args[s->nb_args]` are guarded by `s->nb_args < MAX_NB_ARGS`.
- **`ansi_to_cga[]` lookup**: only accessed with index 0–15 (bounds-checked by the `m >= 30 && m <= 37` / `m >= 40 && m <= 47` conditions and the explicit `index < 16` guard for 256-colour mode).
- **`ff_draw_pc_font`**: writes `fg`/`bg` as `uint8_t` pixel values (no array indexing with them); font index `ch * font_height + char_y` with ch ≤ 255, font_height ≤ 16, char_y < font_height stays within the 2048-byte (CGA) or 4096-byte (VGA16) static tables.
- **Palette write**: `set_palette` writes exactly 256 × 4 = 1024 bytes into `AVPALETTE_SIZE`-sized data[1]; no overflow.
- **Screen-mode switch** (lines 215–270): `av_frame_unref` + `ff_set_dimensions` + `ff_get_buffer` correctly reallocate the frame whenever dimensions change; the `max_pixels=640*480` codec default prevents arbitrarily large allocations from container-controlled width/height.
- **`erase_line` / `hscroll` memset/memcpy**: derived from already-clamped `s->y` and `avctx->height/width`; all offset + length combinations stay within the allocated frame region.
- The `60<<4 = 960` value for mode 17/18 (comment says 480) is a logical mismatch but merely allocates a larger frame; it is not exploitable for OOB access.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
