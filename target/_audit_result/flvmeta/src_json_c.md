After fully reading `json.c` (157 lines) and its headers, I can confirm:

- The file contains only a JSON emitter: `json_print_string()` iterates over a passed `(str, bytes)` pair calling `printf()` per character; all other `json_emit_*` functions simply call `printf()` with fixed or pre-computed values.
- There are **no dynamic memory allocations** (`malloc`/`realloc`/`calloc`), no buffer copies (`memcpy`/`strcpy`/`sprintf` into a buffer), and no array indexing driven by file-supplied values.
- The `json_emitter` struct holds only a single `byte` (`uint8_t`) flag — no embedded buffers or pointers.
- The only technical UB present (`iscntrl(str[i])` and `printf("\\u%.4u", str[i])` with a potentially-negative signed `char`) produces incorrect output at worst, not a memory-safety violation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
