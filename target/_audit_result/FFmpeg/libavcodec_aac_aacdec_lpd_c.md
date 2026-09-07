Complete analysis summary:

**`parse_qn()`**: `qn[2]` stack array, always called with `no_qn=1` — safe.

**`parse_codebook_idx()`**: `nk` bounded by `>25` check before use; `n` is always 3 or 4 (mathematical consequence of the formula); `4*n` ≤ 16 — no integer overflow; inner `kv[i]` loop writes 8 elements to a declared `uint32_t[8]` subarray — no overflow.

**`ff_aac_parse_fac_data()`**: guard `len/8 > 8` is correct; `kv[8][8]` has exactly 8 first-dimension slots; max outer loop iterations = 8 (indices 0–7) — no OOB.

**`ff_aac_ldp_parse_channel_stream()`**: `core_frame_len` is hardcoded to 768 or 1024 (derived from a 3-bit index at line 590); all `fac_len` values flow through the `>8` guard.

Both external call sites (`aacdec_lpd.c:132`, `aacdec_usac.c:1854`) follow identical patterns and are both guarded by the same in-function check.

NO_VULN_FOUND
