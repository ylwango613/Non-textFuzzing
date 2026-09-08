Now I have full context. Let me do the complete analysis with the structure layout confirmed:

- `y_points[14][2]` — `ar_coeffs_y[24]` — `ar_coeffs_uv[2][25]`
- `uv_points[2][10][2]`

**Batch 1 — `ff_aom_parse_film_grain_sets` (lines 124–358):**

- `res[14]` / `res[10]` stack arrays used when `predict_y_scaling`/`predict_uv_scaling` paths copy from `ref`. Ref counts are validated (≤14, ≤10) before ref is stored → no OOB.
- `ar_coeff_lag` from 2 bits → 0-3; `num_y_coeffs = 2*lag*(lag+1)` → max 24 (= `ar_coeffs_y[24]`); UV: +1 → max 25 (= `ar_coeffs_uv[][25]`). Exactly fits.
- `set_idx` is 3 bits → 0-7; `s->sets[8]` → always in range.
- `payload_size * 8` int arithmetic: max 255×8=2040, no overflow.
- `ref` pointer valid throughout: owned by `s->sets[set_idx]` buffer (refcount 1); not freed during the function's normal path.

**Batch 2 — `generate_scaling` (template lines 433–483):**

Critical suspect: line 438 in template:
```c
const int max_value = points[num - 1][0] << shift_x;
```
is evaluated **before** the `if (num == 0) return` check at line 441. When called with `num_y_points=0` + `chroma_scaling_from_luma=1`, this reads `points[-1][0]` — technically OOB. However: (a) `points` = `&aom->y_points[0]`; the preceding struct field is `num_y_points=0`, so bytes 2-3 of that int are read — value is 0; (b) `max_value` is computed but never used (early return takes effect). Result: C undefined behavior at the read level, but zero practical memory-safety impact.

Division by zero in `(0x10000 + (dx>>1)) / dx` when two consecutive y-points share the same x-coordinate (possible if `get_bits(gb, bits_inc)` returns 0) — DoS only, no memory corruption.

**Batch 3 — `sample_lut` and grain application (template lines 175–431):**

- `offsets[bx][by]` with bx,by ∈ {0,1} → `offsets[2][2]` always in bounds.
- `randval` from `get_random_number(8,…)` → 0–255. Max `offx = 3+2*(3+15)=39`, max `offy=39`.
- Worst case luma access `grain_lut[offy+y+32*1][offx+x+32*1]` with y≤1, x≤1 → row=72, col=72; `grain_lut[74][82]` → in bounds.
- `scaling[*src]`: for 8-bit `SCALING_SIZE=256`, pixel 0-255 → in bounds. For HBD `SCALING_SIZE=4096`, pixel clipped to `bitdepth_max` ≤ 4095 → in bounds (for validated decoder output).
- `luma[out->width]` write in padding extension (template line ~518): relies on FFmpeg's standard alignment padding beyond linesize — safe under normal allocation, speculative edge case only.

**Conclusion:** After exhaustive multi-batch analysis of both `aom_film_grain.c` and the included `aom_film_grain_template.c`, no externally-triggerable memory-corruption vulnerability (heap overflow, stack overflow, OOB write, exploitable OOB read) was found. All array indices are properly bounded; the one technical UB (`points[-1]` read when `num==0`) reads from an adjacent struct field with value 0 and the result is discarded by an immediate early return — zero memory-safety impact. The division-by-zero reachable via crafted AFGS1 payload is DoS without memory damage.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
