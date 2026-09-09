Having read the full file and verified all key patterns across the call chain, here is my conclusion:

**Batch 1 findings (lines 1–150):**
- `degrees[]` array has 4 elements; index `transform_type >> 1` is bounded by `> 7` guard → safe
- Film grain: `num_intensity_intervals_minus1` is `uint8_t` (max 255) → `+1 = 256` fits `[256]` array → safe
- `num_model_values` checked `> 6` before use as inner loop bound, matches `[6]` dim → safe

**Batch 2 findings (lines 151–285):**
- `decode_user_data_registered_itu_t_t35`: `data_ref` allocated with `payload_size + padding` bytes; `bytestream2_init` receives `data_length + offset = payload_size` → within allocation; CBS validates `payload_size >= i` → safe
- `decode_user_data_uregistered`: `data_ref` allocated with `payload_size + padding` bytes; `bytestream2_init` receives `data_length + 16 = payload_size` → within allocation; CBS validates `payload_size >= 16` → safe
- `display_elemental_periods = ffi_display_elemental_periods_minus1 + 1`: result 256 truncates to 0 in `uint8_t` field — logic bug, not memory safety
- `size_t → int` conversion for `bytestream2_init buf_size`: would require a multi-GB payload that allocation (ENOMEM) and bitstream exhaustion block before reaching this point

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
