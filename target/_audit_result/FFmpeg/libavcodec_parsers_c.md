The file is 107 lines total. It is a pure registration/iterator file: it declares `extern` references to every parser struct, includes the generated `parser_list.c` array, and exposes one trivial iterator `av_parser_iterate()` that does nothing but index into a static const pointer array and bump a counter. There are no allocations, no size calculations, no memcpy, no data read from external input, and no reachable memory-safety operations of any kind.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
