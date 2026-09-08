**Analysis summary across all 1021 lines:**

**Trellis path/node bounds (lines 97–123, 337–541):**
- `paths[]` allocated as `max_paths = frontier * FREEZE_INTERVAL` via `av_malloc_array` (overflow-safe).
- `pathn` increments once per `nodes_next[pos] == NULL` transition; `nodes_next` is zeroed each outer iteration and has only `frontier` slots, so at most `frontier` increments per outer iteration → total ≤ `frontier * FREEZE_INTERVAL = max_paths`.
- The last allocation writes to `paths[max_paths-1]` (valid); pathn reaches `max_paths` only after the write and is immediately reset to 0 by the freeze. No OOB occurs.
- `av_assert1` is a no-op in release builds without `ASSERT_LEVEL>0`, but the guarded invariant holds structurally.

**node_buf bounds:** `t = node_buf + frontier*(i&1)` — alternating halves, each half exactly `frontier` elements; t advanced at most `frontier` times per outer iteration. Within bounds.

**Per-codec encode paths:** All sample reads stay within `frame->nb_samples` * channels. The SWF `buf[8190]` stack buffer is correctly sized and guarded by `av_assert0(n==4095)`. The IMA_WAV trellis buf `channels*blocks*8` fits exactly. All channel indices are within `status[6]` (max channels = 2 from codec registration).

**Allocations:** All use `av_malloc_array` (via `FF_ALLOC_TYPED_ARRAY`) or `av_malloc` with bounds derived from validated options (`block_size` 32–8192, `trellis` 0–16, `channels` 1–2). No integer overflow path to underallocation found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
