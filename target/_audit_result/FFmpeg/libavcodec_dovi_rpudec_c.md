Now I have all the context needed. Let me trace through all critical paths systematically.

**Batch 1 analysis (lines 0-340):**

- `get_variable_bits` (lines 127–137): `value = (value + 1) << n` with `n=8`—can unsigned-overflow after 3 iterations, but downstream `VALIDATE(emdf_payload_size, 6, 512)` and the `emdf_payload_size * 8 > get_bits_left(gb)` check bound the actual buffer operations.
- `parse_ext_blocks`: `ext->num_static` checked with `>= FF_ARRAY_ELEMS(ext->dm_static)` (=7) and `ext->num_dynamic` checked with `>= FF_ARRAY_ELEMS(ext->dm_dynamic)` (=25) before each insertion. `get_ue_golomb_31` caps `ext_block_length` at 31, so `ext_block_length * 8` is at most 248, no overflow.

**Batch 2 analysis (lines 600–746):**

- `num_pivots` VALIDATE: `num_pivots_minus_2 <= AV_DOVI_MAX_PIECES - 1 = 7`, so `curve->num_pivots <= 9`; `curve->pivots[AV_DOWI_MAX_PIECES + 1]` = `pivots[9]` has exactly 9 slots—safe.
- Inner loop `for i < curve->num_pivots - 1`: max index = 7, arrays sized `AV_DOWI_MAX_PIECES = 8`—safe.
- CRC path at line 733: `rpu_size = get_bits_count(gb) / 8`—minimum bits consumed by reaching this point is well above 8 bits, so `rpu_size >= 1`, no underflow in `rpu_size - 1`.

**`ff_dowi_get_metadata` analysis (lines 50–57):**

`num_ext_blocks` is incremented over `num_static` (max 7) + `num_dynamic` (max 25) = max 32 iterations; `AV_DOWI_MAX_EXT_BLOCKS = 32` and `ext_blocks[32]` is allocated—max index used is 31. Safe.

**Double parse_ext_blocks analysis (lines 702–718):**

- `num_dynamic` reset to 0 before v1; v1 can add up to 25.
- v2 call: any attempt to add more fails with `AVERROR_INVALIDDATA`—properly propagated.
- `num_static` is NOT reset when `dm_compression != 0`, but in that case compressed RPU static blocks go to a stack-local `dummy` variable, so `num_static` can never exceed 7.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
