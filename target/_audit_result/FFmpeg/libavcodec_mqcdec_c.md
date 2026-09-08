All state values from `ff_mqc_nlps`/`ff_mqc_nmps` stay within 0–93 (the 94-element arrays), and all initial `cx_states` values are in the same range. The `bytein` +1 lookahead is guarded by the caller writing sentinel bytes `{0xFF, 0xFF}` into the allocation before any decoding. The allocation itself uses `+ 4` extra bytes, so the sentinels fit. No unchecked externally-controlled sizes, no integer overflows, no buffer writes without bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
