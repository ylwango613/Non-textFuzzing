After reading `msmpeg4.c` (344 lines) and `msmpeg4dec.c` (936 lines) fully, and verifying the RL table infrastructure in `rl.c` and `rl.h`, here is my analysis of each potential concern:

**Scan-table index (`i = -1` for inter blocks):** `ff_rl_init_vlc` stores `run = table_run[idx] + 1` (line 117 of rl.c), so the minimum VLC-decoded `run` for any non-escape coefficient is 1. Inter blocks start at `i = -1`; the first `i += run` always yields `i >= 0`. No `scan_table[-1]` access is reachable from a bitstream.

**`max_level[run>>7][(run-1)&63]` escape-1 (line 758):** `run` from VLC is `>= 1`, so `(run-1)&63 = 0..62`. `max_level[0]` has `MAX_RUN+1 = 65` entries (indices 0–64). Bounded.

**`max_run[run>>7][level/qmul]` escape-2 (line 749):** `level/qmul ≈ table_level`, which is bounded by `MAX_LEVEL = 64`. `max_run[last]` has `MAX_LEVEL+1 = 65` entries. Bounded.

**`ff_v2_dc_lum_table[level+256]` (msmpeg4.c:88-89):** Loop runs `level` from -256 to 255, giving indices 0–511. Table declared as `[512][2]`. Exact fit.

**`rl_table_index` bounds:** `decode012()` → 0/1/2. Used as `ff_rl_table[0..2]` (luma) and `ff_rl_table[3..5]` (chroma). `NB_RL_TABLES = 6`. Bounded.

**`esc3_run_length` / `esc3_level_length`:** Run length gives 3–6 bits (max `run = 63`), `i += run + 1` max yields `i = 63`. Level length gives 2–9 bits. All within bitstream reader bounds.

**`get_dc` division-by-zero:** Minimum DC scale value is 8 (qscale ≥ 1); with `lowres = 3`, `8*8>>6 = 1`. No zero divisor.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
