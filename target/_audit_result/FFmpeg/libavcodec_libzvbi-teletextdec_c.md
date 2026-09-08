Batch 1 (lines 0–600) notes:
- `gen_sub_bitmap`: `resx * resy` product is `int * int`, but libzvbi constrains `page->columns`/`page->rows` to teletext standard (40×25); no overflow path.
- `fix_transparency`: pixel loop bounds are derived from the same `resx`/`resy`; `*pixel += VBI_NB_COLORS` wraps uint8_t but is a logic issue, not memory safety.
- `bprint_color`: accesses `page->color_map[ci]` where `ci` is `vbi_color`; color_map has VBI_NB_COLORS=40 entries, enum values 0–39 — within bounds.
- `slice_to_vbi_lines`: `data_unit_length` is uint8_t (0–255), `+2` = max 257 — no overflow; buf access `buf[4+i]` for i<42 covered by the `data_unit_length+2 > size` guard.
- `subtitle_map[pgno]` where pgno = `((pmag & 7) << 8) + page` ≤ 0x7FF = 2047 — exactly within the 2048-element array.

Batch 2 (lines 600–831) notes:
- `teletext_decode_frame`: `full_pes_size = pkt->size + 45` — potential signed int overflow if pkt->size near INT_MAX, but the `< 184` guard catches negative wrap-around results.
- `handler`: all page buffering uses `av_realloc_array` with nb_pages+1 ≤ MAX_BUFFERED_PAGES (25) — no unbounded growth.
- `subtitle_map[ev->ev.ttx_page.pgno & 0x7ff]` — masked to 2047, within bounds.

All data flow paths from the crafted packet through `slice_to_vbi_lines` → `vbi_decode` → `handler` → `gen_sub_*` respect allocation sizes. The `vbi_page` fields (`rows`, `columns`, `color_map`, `text`) are populated by libzvbi and are constrained to the teletext standard.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
