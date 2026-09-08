The file `hq_common.c` is 44 lines and contains only a static VLC (Variable Length Code) lookup table definition — no dynamic memory allocation, no external input parsing, no pointer arithmetic, and no buffer operations of any kind. The table is a compile-time constant array of `VLCElem` structs built entirely from preprocessor macros with fixed sizes (`1 << HQ_CBP_VLC_BITS` = 32 entries). There is no code path that could receive attacker-controlled input, perform memory allocation, or cause any memory safety issue.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
