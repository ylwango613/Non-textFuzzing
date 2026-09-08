The file is 130 lines of pure function-pointer assignment. The arrays `weight_pixels_tab[4]` and `biweight_pixels_tab[4]` are accessed only at hardcoded indices [0], [1], [2] — all within bounds. There are no memory allocations, buffer copies, or external data reads anywhere in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
