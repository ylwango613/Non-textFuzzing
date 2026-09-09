The file is a minimal 124-line encoder wrapper. It contains no direct memory allocations, buffer copies, or integer arithmetic — all logic is delegated to `ff_qsv_enc_init`, `ff_qsv_encode`, and `ff_qsv_enc_close`. The AVOptions definitions include proper numeric bounds (e.g., `tile_cols` 0–32, `tile_rows` 0–4). As an encoder wrapper, it does not parse untrusted external media input.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
