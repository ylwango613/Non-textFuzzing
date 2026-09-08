Both call sites use `core_frame_len / 8` or `core_frame_len / 16` as `fac_len`. With standard frame sizes (1024), `len_8 = 128` → `128/8 = 16 > 8` → returns `AVERROR_PATCHWELCOME` before any loop. The only loop-running path is when `len/8 <= 8`, keeping `i` in `[0,7]` — within the `kv[8][8]` bounds.

**Summary of findings across all code paths:**

- `kv[8][8]`: guarded by `len/8 > 8` check; `i` is always ≤ 7.
- `qn[2]` stack array in `parse_codebook_idx`: `no_qn` is always `1` at the only call site (`ff_aac_parse_fac_data` line 104), so only `qn[0]` is written.
- `skip_bits(gb, 4*n)`: `n ≤ 4` (when `nk==0`) or `n ≤ 3` (when `nk ≤ 25`); no integer overflow.
- `get_bits(gb, nk)`: `nk ≤ 25`; well within 32-bit limit.
- No heap allocations in this file.
- No `memcpy` calls or pointer arithmetic over user-controlled lengths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
