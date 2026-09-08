After thorough analysis of `ipu_parser.c` (79 lines) and its full dependency chain (`ff_combine_frame`, `ParseContext`, `parser.h`, `parser.c`):

- The IPU parser performs only a byte-by-byte state-machine scan (`state = (state << 8) | buf[i]`) over the caller-supplied buffer with a strict `i < buf_size` bound — no out-of-bounds access.
- `next` is set to `i + 1` where `i < buf_size`, so `next <= buf_size` always satisfies `ff_combine_frame`'s guard at line 227 of `parser.c`.
- No memory allocation occurs in this file; all buffer management is delegated to `ff_combine_frame`, which is a well-hardened shared utility used by ~50 parsers.
- No unchecked `memcpy`, no attacker-controlled size passed to `av_malloc`/`av_realloc`, no fixed-size stack buffer, and no integer arithmetic involving externally-supplied fields.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
