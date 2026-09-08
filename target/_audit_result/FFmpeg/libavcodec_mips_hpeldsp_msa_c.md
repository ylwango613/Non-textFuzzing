After reading all 1,517 lines across three passes and checking the macro definitions and registration site, I have a complete picture.

**Summary of analysis:**

**Batch 1 (lines 1–200):** `common_hz_bil_*` functions. All loop variables are `uint8_t`, heights come from codec framework (4/8/16), `for (loop_cnt = height >> N; loop_cnt--;)` exits immediately when `loop_cnt = 0` — no wrap-around OOB.

**Batch 2 (lines 200–600):** Vertical and HV bilinear variants. `LD_UB(src + 1)` reads 16 bytes starting 1 byte past row-start, but this is standard half-pixel filtering; callers guarantee the extra byte via `AVFrame` padding (`FF_INPUT_BUFFER_PADDING_SIZE`).

**Batch 3 (lines 600–860):** 16-wide HV functions load one extra row beyond the nominal block (`src8`, `src17`). This is expected — half-pixel filtering reads N+1 rows and N+1 columns. Caller padding covers this.

**Batch 4 (lines 860–1200):** `copy_width8_msa` / `copy_16multx8mult_msa`. Use `if (height % N == 0)` chains — no execution if height is zero or doesn't match. `copy_16multx8mult_msa` uses `int32_t cnt/loop_cnt` with `cnt--`; a negative `width` or `height` could create an infinite loop, but these are not directly attacker-controlled (they come from AVCodecContext's coded_width/coded_height which are validated at open time).

**Batch 5 (lines 1200–1517):** Public `ff_put_*/ff_avg_*` wrappers. All pass through to the static helpers above. No allocation, no untrusted size computation.

**No memory allocation, no untrusted size arithmetic, no OOB write path is reachable from a crafted media file through this file alone.** The buffers are pre-allocated AVFrame planes with standard padding; `height` and block width are determined by codec-internal constants, not by raw bytes in the container.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
