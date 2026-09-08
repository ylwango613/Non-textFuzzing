After reading all 645 lines of `refs.c` in batches and tracing every call chain and bounds check:

**Batch 1 (lines 1-600) findings:**
- `ff_hevc_get_ref_list`: `slice_segment_addr` is validated against `ctb_width * ctb_height` before it reaches `ctb_addr_rs_to_ts`; filter.c call sites guard `x0>0`/`y0>0`; mvs.c call site guards `x < sps->width` and `y < sps->height`.
- `alloc_frame`: uses `av_size_mult` for overflow-safe `rpl_bytes` calculation; `ctb_count` product safe (bounded CTB dimensions).
- `init_slice_rpl`: `ctb_addr_ts` values come from `ctb_addr_rs_to_ts` which contains values in `[0, ctb_count)` by construction; `slice_idx` checked against `nb_rpl_elems`.
- Lines 427–428 (`rpl->list[sh->nb_refs[L0]-1]`): `sh->nb_refs[L0]` unsigned-minus-1 underflow concern — but `ff_hevc_slice_rpl` is only called when `slice_type != HEVC_SLICE_I` (hevcdec.c:3042), and for P/B slices `nb_refs[L0]` is always ≥ 1 (`get_ue_golomb_31 + 1`).

**Batch 2 (lines 380–434) loop analysis:**
- Inner loops guard `rpl_tmp.nb_refs < HEVC_MAX_REFS` (16) before every write; `nb_refs[list_idx]` is capped at 15 by parser (hevcdec.c:971 returns error on `>= HEVC_MAX_REFS`), so OOB writes into `rpl->list[i]`/`rpl->ref[i]`/`rpl->isLongTerm[i]` (size 16) cannot occur.
- `short_rps->num_delta_pocs`: both `num_negative_pics` and `nb_positive_pics` are separately validated < HEVC_MAX_REFS (ps.c:221-224), so sum ≤ 30, fits `delta_poc[32]`; `1 << i` shift is safe.

**Batch 3 (generate_missing_ref, lines 465-496):**
- `av_memcpy_backptr(..., 2*(width >> hshift) - 2)`: HEVC mandates minimum frame size aligned to CTB size (≥ 8 px luma → chroma ≥ 4 with 4:2:0), so `2*(width>>1) - 2 ≥ 6 > 0`; no underflow.

All externally-controlled inputs (slice addresses, ref-count fields, RPS sizes) carry validated upper bounds before reaching the memory-operating code in refs.c.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
