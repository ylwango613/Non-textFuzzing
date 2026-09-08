After a thorough audit I have:

1. Read the full `av1_metadata.c` (232 lines) and all relevant headers (`cbs_av1.h`, `cbs_bsf.h`).
2. Traced the CBS core implementation in `cbs.c` — `ff_cbs_insert_unit_content`, `ff_cbs_delete_unit`, `cbs_unit_uninit`, `cbs_write_unit_data`, `ff_cbs_write_fragment_data`.
3. Traced the AV1 CBS write path in `cbs_av1.c` — `cbs_av1_write_obu` and the per-OBU-type dispatch.
4. Verified `av_reduce` (rational.c) inputs/outputs for the `tick_rate` path.

Key findings per audit scope:

- **TD OBU insertion** (`&ctx->td_obu`, `content_ref=NULL`): The struct member lives for the entire BSF lifetime. `cbs_unit_uninit` only NULLs `unit->content`; it does not `av_free` it. No UAF.
- **TD write path**: `cbs_av1_write_obu` reads `unit->content` and calls `cbs_av1_write_temporal_delimiter_obu` which does not access `obu->obu.*` (the union), only the header. No OOB access.
- **Sequence header `make_unit_refcounted`**: Only called for the SEQUENCE_HEADER case, not TD. No issue for the injected unit.
- **`av_reduce` overflow**: `ctx->tick_rate` is `AVRational {int, int}`, so `.num` and `.den` are bounded by `INT_MAX` before the call. GCD reduction can only decrease them. No signed overflow.
- **Loop bounds on `frag->units`**: Both the padding-deletion loop and the sequence-header scan are properly bounded by `frag->nb_units`.
- **`ff_cbs_delete_unit` with position 0**: Guarded by `frag->nb_units && frag->units[0].type == AV1_OBU_TEMPORAL_DELIMITER`; the assert inside `ff_cbs_delete_unit` also enforces `0 <= position < frag->nb_units`.

No externally-triggerable memory safety vulnerabilities were found in `av1_metadata.c` or in its direct call chain within the scope of this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
