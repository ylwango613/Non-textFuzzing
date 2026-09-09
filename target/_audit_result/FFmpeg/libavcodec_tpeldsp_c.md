The analysis is complete. Summary of findings:

- `tpeldsp.c` is a pure DSP helper (334 lines) — no allocation, no input parsing.
- All pixel functions loop over `width × height` accessing `src[j]`, `src[j+1]`, `src[j+stride]`, and `src[j+stride+1]`. The one-pixel-beyond reads are intentional: svq3.c calls `emulated_edge_mc` with `width+1, height+1` when near frame edges, providing the required padding.
- The `dxy` index into `put_tpel_pixels_tab[11]` / `avg_tpel_pixels_tab[11]` is computed as `(mx mod 3) + 4*(my mod 3)` — mathematically bounded to {0,1,2,4,5,6,8,9,10}, never reaching uninitialized slots [3] and [7], and never exceeding array bounds (max = 10).
- No `av_malloc`, `memcpy`, or any direct handling of container-supplied sizes in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
