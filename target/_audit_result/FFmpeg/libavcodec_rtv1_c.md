After completing the full analysis, I have examined:
- The entire `rtv1.c` (150 lines)
- `texturedsp.h` and `texturedsp.c` (`dxt1_block_internal` implementation)
- `bytestream.h` (safe vs. unsafe `u`-variant macros)
- `utils.c` (`ff_set_dimensions` → `av_image_check_size2`)

Key conclusions:
1. **Bytestream reads** are all correctly bounded: unsafe `u`-variants are preceded by explicit `bytestream2_get_bytes_left` checks; the raw bitmap read at line 70 uses the safe (self-checking) `bytestream2_get_le32` (not the `u` variant).
2. **Output buffer writes** in both paths (mode=1 `AV_WL32` at line 84; `dxt1_block` at lines 52/73/77) remain within the allocated `FFALIGN(width,4) × FFALIGN(height,4)` frame.
3. **Integer overflow in `width * 4`** (inner-loop bound): would only make the loop never execute — not cause OOB writes. In practice, `av_image_check_size2` rejects any width large enough to overflow `width * 4` before allocation occurs (`stride = 8LL*w ≥ INT_MAX` rejection path).
4. **`run` mechanism**: run-length repeats always stay within the per-row `x < width*4` and per-frame `y < height` loop bounds.
5. **Dimension guards**: `width > INT_MAX-4U` check catches negative/huge values; `av_image_check_size2` rejects zero, overflow-inducing, or too-large dimensions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
