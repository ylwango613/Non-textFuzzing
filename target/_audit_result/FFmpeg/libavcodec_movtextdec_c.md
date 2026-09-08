`bytestream_get_buffer` is a raw `memcpy` with no internal bounds checking — all safety depends on the caller's `remaining` tracking in `mov_text_tx3g`. I've now verified the offset accounting is correct (BOX_SIZE_INITIAL=40 covers exactly the fixed-layout header; the 2-byte `ftab_entries` read lands at indices 38–39, within bounds), and `decode_styl`'s pre-check `2 + style_entries * 12 > size` properly gates all subsequent reads against the packet-validated `tsmb_size`. `av_realloc_array` with nmemb=0 internally calls `realloc(ptr, 1)` (via `size + !size`), so no NULL-deref; `text_to_ass` guards every `m->s[entry]` access with `entry < m->style_entries`.

After exhaustive multi-pass analysis of every data path in `movtextdec.c` — including `mov_text_tx3g`, `decode_styl`, `decode_hlit`, `decode_hclr`, `decode_twrp`, `text_to_ass`, and the box-parsing loop in `mov_text_decode_frame` — no externally-triggerable memory-safety vulnerabilities were found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
