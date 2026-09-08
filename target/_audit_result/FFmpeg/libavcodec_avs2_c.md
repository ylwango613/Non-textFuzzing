**Analysis complete.**

`avs2.c` contains exactly 43 lines: a license header, `#include "avs2.h"`, and a single `const AVRational ff_avs2_frame_rate_tab[16]` static data table. There is zero executable code, no memory allocations, no pointer arithmetic, and no processing of external input.

The only callers of this table:
- `avs2_parser.c:119`: index = `get_bits(&gb, 4)` → 0–15 → within bounds of a 16-element table. Safe.
- `libdavs2.c:89`: guarded by explicit `if (headerset->frame_rate_id < 16)` check. Safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
