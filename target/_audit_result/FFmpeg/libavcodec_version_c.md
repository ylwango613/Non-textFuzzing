`version.c` contains only three trivial functions: a version integer getter with `static_assert` compile-time checks, a configuration string getter, and a license string getter that uses a compile-time string-literal index trick. There is no memory allocation, no external input parsing, no buffer manipulation, and no runtime arithmetic on untrusted data. The file introduces zero attack surface.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
