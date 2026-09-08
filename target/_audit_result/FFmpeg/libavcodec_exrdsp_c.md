I've completed the full analysis. Let me summarize what I found:

**`predictor_scalar` (lines 41-57):**
- The even-size branch accesses `src[0]` and `src[1]` before any size check — could be OOB if `size == 0`. However, all callers prevent this: `zip_uncompress` validates `dest_len == uncompressed_size` (uncompress fails if output is 0 bytes); the scanline path at line 1337 rejects `data_size > uncompressed_size` (data_size is forced > 0); the DWA path guarantees `dc_count >= 3` via its `dc_count != dc_w * dc_h * 3` check.
- The loop accesses `src[i+1]` where `i < size`. This is safe because the `if` branch guarantees `size` is always **odd** when the loop runs, so the last `i = size-2` yields `src[size-1]`, which is within bounds.

**`reorder_pixels_scalar` (lines 27-39):**
- `half_size` is declared `int` while `size` is `ptrdiff_t`. For very large sizes (> `2*INT_MAX`), this could truncate to a negative int, making `t2 = src + half_size` point before `src`. However, the loop condition `i < half_size` with a negative `half_size` is immediately false — no actual memory accesses occur. Not exploitable.
- Reads are bounded to `[0, 2*half_size-1]` which is ≤ `size-1`. Writes to `dst` span `2*half_size` bytes, and callers allocate `uncompressed_size + 64` bytes for `dst`. No OOB.

**Conclusion:** `exrdsp.c` contains only 70 lines of straightforward scalar DSP helpers with no heap allocations. All size parameters are validated by callers before these functions are invoked. No externally-triggerable memory safety vulnerabilities exist in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
