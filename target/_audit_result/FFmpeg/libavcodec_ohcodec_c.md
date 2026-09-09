`ohcodec.c` is complete at 79 lines. The file contains three pure utility functions: an error-code mapping switch/case, and two pixel-format lookup functions that iterate over a compile-time-bounded array using `FF_ARRAY_ELEMS()`. The header adds one more inline MIME-type switch/case. None of these functions perform memory allocation, pointer arithmetic, memcpy, or process any external/user-controlled input — they are purely value-mapping helpers with no memory operations whatsoever.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
