MACEtab4 has exactly 128 rows (32 lines × 4 entries/line = 128 rows `[0,127]`). The mask `& 0x7f0 >> 4` hard-caps the row index to 127 regardless of `chd->index` value. All accesses stay within bounds.

**Complete audit summary for `mace.c`:**

- **No heap allocation**: The only buffer obtained is via `ff_get_buffer`, governed by `nb_samples`.
- **`nb_samples` overflow**: Explicitly guarded at line 256 (`if (nb_samples > INT_MAX) return AVERROR_INVALIDDATA`).
- **Channel count**: Validated to `[1,2]` in `mace_decode_init`; division by `channels` is safe.
- **Lookup table row index**: `(chd->index & 0x7f0) >> 4` is always `∈ [0, 127]`; MACEtab2 and MACEtab4 both have exactly 128 rows — no OOB.
- **`val` ranges**: Extracted from packet bits — `(pkt>>5)∈[0,7]`, `(pkt>>3)&3∈[0,3]`, `pkt&7∈[0,7]` — all valid for their respective `tab1` arrays (MACEtab1 has 8 entries, MACEtab3 has 4 entries).
- **Input buffer reads**: Mathematical verification shows max index = `buf_size - 1`.
- **Output buffer writes**: `nb_samples` allocated equals exactly the number of samples the loop produces.
- **`chd->index` int16_t**: Feedback loop equilibrium keeps it `∈ [0, ~8000]`; it cannot wrap into negative undetected (the `< 0` guard catches any wrap).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
