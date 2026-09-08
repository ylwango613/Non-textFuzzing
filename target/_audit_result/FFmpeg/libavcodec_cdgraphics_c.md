After a complete read and analysis of all 405 lines, I verified:

**Packet size bounds** (lines 276-283): strictly clamped to `[CDG_MINIMUM_PKT_SIZE=6, CDG_HEADER_SIZE+CDG_DATA_SIZE=24]`.

**`cdg_tile_block`** (lines 141-163): `ri` and `ci` are bounds-checked before the pixel loop; max pixel access is row 215, col 299 — within the fixed 300×216 frame.

**`cdg_scroll`** (lines 204-264): `h_off` clamped via `FFMIN` to max 5, `v_off` to max 11; `hinc` therefore ≤ 11, `vinc` ≤ 23. The main `memcpy` length is `FFABS(stride) - FFABS(hinc)` ≥ stride−11 ≥ 289, never negative or overflowing. All `cdg_fill_wrapper` row/column arguments stay within `[0, CDG_FULL_HEIGHT)` and `[0, CDG_FULL_WIDTH)`.

**`cdg_load_palette`** (lines 123-129): accesses `data[0..15]` over a 16-byte `cdg_data` array — within bounds.

**`CDG_INST_TRANSPARENT_COL`** (lines 352-353): `CDG_PALETTE_SIZE = CDG_DATA_SIZE = 16`; all 16 `alpha[]` and `cdg_data[]` accesses are within bounds.

**Frame dimensions** are compile-time constants (`CDG_FULL_WIDTH=300`, `CDG_FULL_HEIGHT=216`), not attacker-controlled; no integer-overflow path to underallocation exists.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
