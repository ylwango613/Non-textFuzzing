Now I have a complete picture. Let me summarize my analysis across all sections of the code:

**Group 1 — `dirac_dwt.c` (82 lines):** Wrapper only; calls `spatial_idwt_init_{8,10,12}bit` and `ff_spatial_idwt_slice2`. No direct buffer operations; no issue.

**Group 2 — `dirac_dwt_template.c` horizontal compose functions (lines 65–202):** Checked all five horizontal compose functions for OOB access:
- `horizontal_compose_dd137i` accesses `b[-1]` (line 114) when `w=2` and `b[w]`/`b[w+1]` (lines 110–111) when `w=4`. However, the `buf_base` allocation in `diracdec.c` uses `CALC_PADDING(w, MAX_DWT_LEVELS)` + FFALIGN, making the allocated stride much wider than the DWT level width. Both the `b[-1]` read (lands in the top-padding area of `buf_base`) and `b[w]` reads (land in the zero-initialized padding within the same row) are within the allocated contiguous buffer. This is a correctness/logic bug, not an exploitable OOB.
- `tmp[-1]` and `tmp[w2+1]` writes in dd97i/dd137i are safe because `d->temp` is advanced by 8 TYPE elements in `spatial_idwt_init`, giving 8-element headroom for negative indexing.

**Group 3 — `spatial_idwt_init` (lines 519–605):** The `d->temp += 8` advancement is on a local DWTContext each call (re-initialized from `p->idwt.tmp` in `ff_spatial_idwt_init`), so no cumulative drift. `DWTCompose.cs` array is bounded by `MAX_DECOMPOSITIONS=8` and `decomposition_count <= MAX_DWT_LEVELS=8`. No issue.

**Group 4 — Vertical compose and spatial compose slice functions (lines 339–477):** Row pointers use `av_clip` or `avpriv_mirror` to clamp, and the `DWTCompose.b[MAX_DWT_SUPPORT]` array (8 elements) is never over-indexed: dd97i uses b[0..5], dd137i uses b[0..7], daub97i uses b[0..3].

**Group 5 — `diracdec.c` allocation/init context:** `CALC_PADDING` ensures the DWT width at every level is at least 2. `av_calloc` zero-initializes, making any incidental boundary reads return zeros. No controllable OOB write path identified.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
