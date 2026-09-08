**Analysis summary across all code paths:**

**`scantag` (lines 102-122):** Loop bound `len < 128` ensures writes to `buffer[0..127]` only. On `>` found, `buffer[len] = '\0'` at most at index 127. On loop exhaustion it returns 0 without touching `buffer[128]`. Safe.

**`face=` attribute / `param[-1]` (lines 270-275):** `param` is always derived from within `buffer[128]` via `scantag`. After `param += 5 + (param[5]=='"')`, `param[-1]` refers to the `=` or `"` character still within `buffer`. `strcspn` result is bounded by the buffer size (~128 max). `av_strlcpy` with `FFMIN(sizeof(face), len+1)` is safe.

**Font stack[16] (lines 228-255):** Push guard `sptr < 15` → accesses `stack[sptr+1]` at most `stack[15]`. Pop guard `sptr > 0` → accesses `stack[sptr]` at most `stack[15]` and `stack[sptr-1]` at most `stack[14]`. No OOB.

**Memory allocation:** No `malloc`/`av_malloc`/`av_realloc` calls exist in this file at all. All output growth is via `AVBPrint` which manages dynamic resizing internally.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
