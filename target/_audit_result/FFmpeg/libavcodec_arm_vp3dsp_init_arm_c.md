The file is 45 lines — a pure CPU-dispatch initializer that checks NEON support and assigns function pointers. No memory allocation, no external data parsing, no arithmetic, no buffer operations. Nothing in this file can be triggered by attacker-controlled input.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
