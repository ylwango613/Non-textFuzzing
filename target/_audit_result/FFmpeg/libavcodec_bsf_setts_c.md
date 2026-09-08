I've completed a thorough review of `setts.c`:

- The `var_values[]` array is declared as `double var_values[VAR_VARS_NB]` (21 elements); all accesses use statically-bounded enum indices (0–20). No OOB.
- `av_packet_alloc/move_ref/ref/unref/free` usage is correctly ordered with no double-free or use-after-free.
- On `AVERROR_EOF`, `ff_bsf_get_packet_ref` does not touch `pkt` (returns immediately per bsf.c:258-259); `pkt->pts/dts/duration` reads on the EOF path access fixed-size struct fields only — no pointer dereference.
- No `av_malloc`/`memcpy`/`av_realloc` with attacker-controlled sizes.
- No extradata, chunk-size, or index-table parsing.
- Expression strings are user-supplied CLI options, not container-derived fields; they feed into `av_expr_parse`/`av_expr_eval` producing `double` results — no memory allocation gated on their content.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
