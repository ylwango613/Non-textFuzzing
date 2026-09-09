After thorough analysis of the 102-line `videodsp_template.c` and its calling context:

**Group 1 (Lines 1-35): Headers, function signature, early returns**
- `av_assert2` at line 36 is `((void)0)` in release builds (ASSERT_LEVEL ≤ 1, confirmed in avassert.h). The guard on `block_w * sizeof(pixel) <= FFABS(buf_linesize)` is disabled at runtime.
- No exploitable path here because the early return at line 33-34 (`!w || !h`) prevents zero-dimension exploitation.

**Group 2 (Lines 38-54): src pointer clamping**
- `src -= src_y * src_linesize` (line 39): `int × ptrdiff_t → ptrdiff_t`. Would require `src_y` near `INT_MAX` for overflow, but frame coordinates are bounded by codec dimension limits.
- Line 49 signed-to-unsigned: `(1 + src_x - w) * sizeof(pixel)` — comment acknowledges conversion hazard, but the `src_x >= w` guard ensures positivity. Integer overflow of `1 + src_x` would require `src_x = INT_MAX`, impossible from frame coordinates.

**Group 3 (Lines 55-65): bounds computation and variable shadow**
- `end_x = FFMIN(block_w, w-src_x)` at line 59 uses parameter `w`; line 63 overwrites local `w = end_x - start_x`. Variable shadowing is a code smell but not exploitable.
- After clamping, `end_x ≥ 1` always (verified by all clamping branches), so `bufp[end_x-1]` at line 98 cannot be negative-index OOB.

**Group 4 (Lines 68-101): copy loops and left/right fill**
- `memcpy(buf, src, w * sizeof(pixel))`: `w = end_x - start_x ≤ block_w`. Safety relies on the disabled `av_assert2` guarantee.
- All known callers (VP8: `EDGE_EMU_LINESIZE=32` with `block_w≤17`; MPEG: `linesize` always ≥ `17`; VVC: `EDGE_EMU_BUFFER_STRIDE<<ps` is oversized) enforce the invariant externally.
- Line 87 backward pointer restore: `block_h × buf_linesize` subtraction is exact because the loops advanced `buf` by exactly that amount; no net error.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
