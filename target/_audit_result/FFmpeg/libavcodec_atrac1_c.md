**Findings summary across all analysis groups:**

**Group 1 (lines 1–100): Struct definitions, constants, `at1_imdct()`**
- `mdct_ctx[nbits - 5 - (nbits > 6)]` → valid indices 0/1/2 for nbits ∈ {5,7,8}, protected by the explicit `nbits` check in the caller.

**Group 2 (lines 111–166): `at1_imdct_block()`**
- `memcpy(q->bands[band_num] + 32, ..., 240 * sizeof(float))` at line 157:
  - For band_num=0 (low, 128-sample band): writes indices [32..271] into `q->low[256]` → OOB by 16 floats into `q->mid[0..15]`.
  - For band_num=1 (mid): writes indices [32..271] into `q->mid[256]` → OOB by 16 floats into `q->high[0..15]`.
  - However, in the very next loop iteration, `vector_fmul_window` writes 32 floats to `q->bands[band_num][0..31]`, **overwriting the OOB region before it is read**. The corruption is self-healing within one frame and cannot be leveraged for memory corruption.
- `ref_pos`, `start_pos`, and `pos` accumulators all stay within spectrum[0/1][512] bounds.

**Group 3 (lines 172–257): `at1_parse_bsm()`, `at1_unpack_dequant()`**
- `num_bfus` bounded by `bfu_amount_tab1` ≤ 52 = AT1_MAX_BFU; both `idwls[52]` and `idsfs[52]` stay in range.
- `pos + num_specs - 1` = max 492+19 = 511 ≤ spec[511]; no OOB write to `q->spec[512]`.
- Bitstream overflow guard (line 235) enforced before any spectral read.

**Group 4 (lines 260–403): `at1_subband_synthesis()`, `atrac1_decode_frame()`, init/cleanup**
- `channels` validated to [1..8] in `atrac1_decode_init` before `q->SUs[ch]` access.
- `buf_size < 212 * channels` check guards `init_get_bits` and `buf[212 * ch]` access.
- `av_tx_init` called with fixed, safe sizes (32, 128, 256).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
