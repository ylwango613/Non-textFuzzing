After a thorough multi-pass analysis of `sbc.c` (all 270 lines) and the full call chain through `sbcdec.c`, I verified every externally-controlled field and array access:

- **`ff_sbc_crc8()`**: `data[byte_length]` is guarded; bit loop is bounded by `len`.
- **`ff_sbc_calculate_bits()`**: `sbc_offset4[sf][sb]` and `sbc_offset8[sf][sb]` — `sf` is always 0–3 (masked via `& 0x03` or hardcoded 0 for MSBC); `sb` is 0–3 or 0–7 matching the array dimensions [4][4] and [4][8]. `bitneed[2][8]` stack array only accessed with `ch` ∈ {0,1} and `sb` < `subbands` ∈ {4,8}. `bits[ch][sb]` clamped to ≤ 16.
- **`sbc_unpack_frame()`**: All bit-field extractions bitmask-bounded; `crc_header[crc_pos>>3]` max index is 10 within `[11]`; `frame->sb_sample[blk][ch][sb]` with blk ≤ 15, ch ≤ 1, sb ≤ 7 all within `[16][2][8]`; audio-sample loop has an explicit `consumed > len * 8` guard.
- **`sbc_synthesize_four/eight()`**: `offset[i]` (i up to 15) within `[16]`; `v[offset[i] + N]` max index 159+9=168 within `V[170]`; output plane writes stay within `nb_samples * sizeof(int16_t)`.
- **`sbc_decode_frame()`**: `nb_samples = blocks * subbands` max 128; channel layout set before `ff_get_buffer()`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
