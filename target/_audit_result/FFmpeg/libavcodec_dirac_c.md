After a complete analysis of the entire file plus call-chain tracing:

**Bounds checks verified clean:**

| Check | Result |
|---|---|
| `frame_rate_index > 10U` → `ff_mpeg12_frame_rate_tab[1..8]` (16 entries) | ✓ |
| `aspect_ratio_index > 6U`, then `[index-1]` on 6-entry array | ✓ |
| `pixel_range_index > 4U`, after adjustment 2-4, `[index-2]` on 3-col array | ✓ |
| `pixel_range_presets[pixel_range_index-1]` — values 1-4, index 0-3, 4-entry array | ✓ |
| `color_spec_index > 4U` → `dirac_color_presets[idx]` 5-entry array | ✓ |
| `primaries idx < 3U` → `dirac_primaries[idx]` 3-entry array | ✓ |
| `chroma_format > 2U`, `dirac_pix_fmt[0..2][0..2]` | ✓ |

**`color_spec_index` assignment chain (line 288):** `idx = dsh->color_spec_index = get_interleaved_ue_golomb(gb)` — the inner assignment truncates `uint32_t → uint8_t`; C assignment-chain semantics make `idx` receive the already-truncated `uint8_t` value. So both `idx` (used in `dirac_color_presets[idx]`) and the checked `dsh->color_spec_index` hold the same truncated, bounded value. No OOB.

**Width/height without upper bound:** Stored as `unsigned int`, no max check in `dirac.c`. `diracdec.c` guards with `max_pixels`; `oggparsedirac.c` assigns to `int` fields (semantic issue, not heap corruption). No allocation in `dirac.c` itself uses these dimensions.

**Only allocation in dirac.c:** `av_mallocz(sizeof(*dsh))` — fixed size, no user-controlled size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
