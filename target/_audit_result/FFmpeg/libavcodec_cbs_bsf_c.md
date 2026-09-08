After fully reading `cbs_bsf.c` (199 lines) and its key headers (`cbs_bsf.h`, `cbs.h`), and verifying the relevant function signatures:

- **`memcpy` at line 91**: `side_data` is allocated with exactly `frag->data_size` bytes via `av_packet_new_side_data(..., frag->data_size)`, and `memcpy` copies exactly `frag->data_size` bytes — no overflow possible.
- **`frag->data_size`** is `size_t`; `av_packet_new_side_data` also takes `size_t` — no signed/unsigned truncation.
- **Fragment reset paths**: all error returns (from `update_fragment`, `ff_cbs_write_fragment_data`, `av_packet_new_side_data`) leave the fragment unreset in `cbs_bsf_update_side_data`, but the caller (`ff_cbs_bsf_generic_filter`) unconditionally calls `ff_cbs_fragment_reset(frag)` on the `fail` path — no double-free, no leak of fragment data.
- **`ff_cbs_bsf_generic_init`**: if `ff_cbs_init(&ctx->output)` fails, `ctx->input` is not closed — a resource leak, but not a memory-safety (corruption) issue.
- The file is a thin framework glue with no direct parsing of attacker-controlled integer fields, no `av_malloc` with user-derived sizes, and no array indexing on untrusted values.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
