All enum values confirm:
- `N_TXFM_SIZES = 4` → `itxfm_add[5][...]` accommodates index 4 (lossless `iwht`) exactly
- `N_FILTERS = 4` → `mc[5][4][2][2][2]` - all accesses in the init code use indices 0-4/0-3/0-1/0-1/0-1, all in-bounds

**Analysis summary:**

The file is a 260-line pure NEON dispatch initialization file. Key analysis points:

1. **`define_8tap_2d_fn` stack buffer** (line 49): `LOCAL_ALIGNED_16(uint8_t, temp, [((1 + (sz < 64)) * sz + 8) * sz])` — the buffer size is a compile-time constant per `sz` value. The write of `(h + 8) * sz` bytes is safe because VP9 guarantees `h ≤ (1 + (sz < 64)) * sz` for all valid block sizes (including non-square: sz=16 with h=32, sz=32 with h=64). The formula was designed to cover these exactly.

2. **Array index accesses** in `vp9dsp_mc_init_aarch64`, `vp9dsp_itxfm_init_aarch64`, and `vp9dsp_loopfilter_init_aarch64` — all indices (0-4, 0-3, 0-2, 0-1) are compile-time constants within the declared array dimensions.

3. **No external input** flows into this file at all — it only executes at codec init time to populate function pointers based on CPU feature flags, with no attacker-controlled data involved.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
