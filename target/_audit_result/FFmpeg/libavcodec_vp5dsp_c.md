Complete picture: `edge_emu_buffer_alloc` is 32×stride bytes, edge filter accesses rows 8–11 (for ver) and columns 8–11 (for hor) within a 16×12 copy buffer, with `dx&7`/`dy&7` guaranteeing all offsets are in [1,7]. The file has no malloc/free, no external-input parsing, and the negative-index pointer arithmetic is a bounded deblocking design pattern. All accesses stay within the pre-validated buffer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
