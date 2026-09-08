The file is 36 lines of pure CPU-dispatch initialization — it only reads CPU flags and conditionally assigns one function pointer. No memory allocation, no data parsing, no arithmetic on external inputs. The NEON assembly kernel (`huffyuvdsp_neon.S`) is a straightforward vectorized add-and-mask loop with no allocation; bounds correctness there depends entirely on caller-supplied `w`, not on anything in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
