After thoroughly reading the file in batches and analyzing all key patterns, I have completed the audit of this file.

**Summary of findings per section:**

- **Lines 1–305 (macros):** Pure SIMD computation macros, no memory management.
- **Lines 307–1002 (horiz_mc_qpel_* functions):** All use `uint8_t loop_count = (height >> 2)`. Height is always passed as the compile-time constant 8 or 16 from the `ff_*` wrappers. No attacker-controlled sizes. Writes are fixed-stride stores (ST_D4/ST_UB) into caller-supplied buffers sized by the MPEG decoder.
- **Lines 1004–2714 (vert_mc_qpel_* functions):** Unrolled fixed-count load/store sequences for 8x8 and 16x16 blocks; entirely hardcoded.
- **Lines 2715–3670 (hv_mc_qpel_no_rnd_* with buff[272]):** Each function allocates `uint8_t buff[272]` and calls a horizontal pass with `height=16, dst_stride=16`. The loop writes 4 rows × 4 iterations = 16 rows, then one extra final `ST_UB` writes row 17 at buff[256..271]. buff is exactly 272 = 17×16 bytes — tight but correct by design. The vertical pass subsequently reads all 17 rows (inp0..inp16) from buff. No overflow.
- **Lines 3772–6470 (hv_mc_qpel_aver_* and ff_* wrappers):** Same pattern; all `buff[272]` cases are consistent. Wrappers pass only compile-time sizes (8 or 16) to internal static functions; no attacker-controlled width/height.

No dynamic memory allocation, no untrusted-size arithmetic, no OOB-write paths, no integer overflow in allocation sites.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
