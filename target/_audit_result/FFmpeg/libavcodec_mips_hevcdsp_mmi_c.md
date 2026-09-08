After a thorough multi-pass read of all 1146 lines, cross-referencing the constants (`MAX_PB_SIZE=64`, `QPEL_EXTRA=7`, `EPEL_EXTRA=3`) from the headers, and tracing the filter-index bounds back to the call site (`mx = mv->x & 3` in hevcdec.c:1733, `mv->x & 3` for QPEL gives [0,3]; `av_zero_extend(mv->x, 3)` for EPEL gives [0,7]):

- **Stack buffers**: `tmp_array[(MAX_PB_SIZE + QPEL_EXTRA) * MAX_PB_SIZE]` = 71×64×2 = 9088 bytes; every assembly row-stride is exactly 0x80 = 128 bytes, and the maximum fill is `(height + QPEL_EXTRA) × 128` bytes, which equals the buffer exactly when `height = MAX_PB_SIZE = 64`. The HEVC decoder enforces this bound before dispatching through the function-pointer table.
- **Filter table accesses**: `ff_hevc_qpel_filters[4]` indexed with `mx ∈ {0,1,2,3}`; `ff_hevc_epel_filters[8]` indexed with bounded `mx` — no OOB.
- **Source reads**: offset by `QPEL_EXTRA_BEFORE`/`EPEL_EXTRA_BEFORE` rows and columns, which are guaranteed by the reference-frame padding the decoder allocates before dispatch.
- **Assembly write patterns**: all inner/outer loop step adjustments are internally consistent (net per-row tmp advance = 128 bytes in every macro instantiation).

No externally triggerable memory-safety vulnerability was found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
