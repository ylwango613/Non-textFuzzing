Complete analysis done. The `ff_lzw_decode` loop decrements `l` from `len` and stops when it reaches zero, so it never writes more than `len` bytes — the `idx_line` buffer is safe. `av_image_check_size` is called by `ff_set_dimensions` and rejects dimensions that would cause linesize×height to overflow, guarding the `av_fast_malloc` in the restore-disposal path. Palette indices are `uint8_t` (0–255) into 256-entry fixed arrays. All bytestream reads are bounds-checked. No cross-keyframe disposal confusion exists because `gce_prev_disposal` is reset to `GCE_DISPOSAL_NONE` at the start of each keyframe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
