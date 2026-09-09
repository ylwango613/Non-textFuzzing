The file `libavcodec/reverse.c` is a one-line wrapper that includes `libavutil/reverse.c`. That file contains only a single `const uint8_t ff_reverse[256]` lookup table — a statically initialized, fixed-size, read-only array. There are no functions, no dynamic memory allocation, no pointer arithmetic, no input parsing, and no memory operations of any kind.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
