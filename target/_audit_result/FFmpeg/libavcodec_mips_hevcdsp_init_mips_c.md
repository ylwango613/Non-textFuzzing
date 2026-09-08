The file is a pure function-pointer dispatch table initializer. All array indices are compile-time constants within the declared bounds (`[10][2][2]`, `[5]`, `[4]`), there are no memory allocations, no buffer reads/writes, and no untrusted input is processed. No memory safety vulnerabilities exist in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
