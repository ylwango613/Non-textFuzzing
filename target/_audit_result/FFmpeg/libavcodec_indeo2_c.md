After complete analysis, I've verified all the key data paths:

**Key findings:**

1. **VLC codes (c) range**: `ir2_get_code` returns 0x01..0x7F (delta) or 0x80..0x8F (skip). Max c for table index: `c * 2 + 1 ≤ 0x7F * 2 + 1 = 0xFF = 255`. Table `ir2_delta_table[*]` has 256 entries — no OOB.

2. **`ltab/ctab` bounds**: `ltab = buf[0x22] & 3` → 0–3; `ctab = buf[0x22] >> 2` → validated `if (ctab > 3)` before use. Both index into `ir2_delta_table[4]` — no OOB.

3. **`dst[out]` in delta path**: `out` is always **even** (starts at 0; skip adds `c*2`; delta path uses `out++; out++;`). `width` is always even (checked at entry). So when entering the delta branch, `out ≤ width−2`, writing to `dst[out]` and `dst[out+1]` stays ≤ `dst[width−1]` — no OOB.

4. **`ir2_decode_plane_inter` missing bounds check**: The skip path (`out += c*2`, no `if (out+c*2 > width)` guard) differs from `ir2_decode_plane` but is **not exploitable**: the skip path never writes to `dst`; after `out ≥ width` the `while` loop exits. No OOB write.

5. **`dst[out - pitch]` in `ir2_decode_plane`**: Only accessed when `j ≥ 1`, meaning `dst` has already been advanced by `pitch`. Valid access to the previous row.

6. **No heap allocations with user-controlled sizes** in this file. `ff_reget_buffer` uses codec-validated dimensions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
