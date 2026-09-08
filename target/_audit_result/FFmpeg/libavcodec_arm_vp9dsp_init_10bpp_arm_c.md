I now have full context. Let me verify the stack buffer sizing logic vs. max VP9 block heights.

The `define_8tap_2d_fn` macro (template line 39–54) allocates a stack buffer of size `((1 + (sz < 64)) * sz + 8) * sz * 2` bytes, then writes `(h + 8) * (2 * sz)` bytes into it via the horizontal filter pass. An overflow requires `h > (1 + (sz < 64)) * sz`.

Checking each sz against VP9's maximum block heights:
- sz=64 → limit=64, VP9 max height for 64-wide = 64 ✓
- sz=32 → limit=64, VP9 max height for 32-wide = 64 ✓
- sz=16 → limit=32, VP9 max height for 16-wide = 32 ✓
- sz=8  → limit=16, VP9 max height for 8-wide  = 16 ✓
- sz=4  → limit=8,  VP9 max height for 4-wide  = 8  ✓

The buffer is sized exactly for the maximum valid VP9 block heights; no overflow is reachable with conformant decoder input. The rest of the file is pure function-pointer assignments with no memory allocation or external data parsing. There are no exploitable memory safety issues in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
