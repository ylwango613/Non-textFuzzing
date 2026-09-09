All bounds verified:
- `subframe_scale` max = 128 (correct operator precedence), max product = 8064 — no `int16_t` overflow
- `nb_samples` max = 16384 < 32767 (`int16_t` limit) — last subframe assignment never overflows
- `s->residues[544]` max access index = 543 for all 16 possible `filter_order` values (proven computationally)
- `coding_mode[128]` accessed only at indices 0–127 (protected by `i == wlength` break before the `while` condition)
- Channel indices ≤ 5 < `TAK_MAX_CHANNELS` = 16 always
- `decode_residues` guard `length > s->nb_samples` prevents OOB writes into the decoded sample buffer
- `filter_order > subframe_size` and `left ≤ 0` guards prevent pointer arithmetic underflow

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
