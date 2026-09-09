The file is only 114 lines — a thin encoder registration wrapper that delegates entirely to `ff_qsv_enc_init`, `ff_qsv_encode`, and `ff_qsv_enc_close`. There is no memory allocation, no parsing of external/attacker-controlled data, no buffer arithmetic, and no index arithmetic in this file. It is a hardware encoder (not a decoder or demuxer), so it does not process untrusted media container bytes directly.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
