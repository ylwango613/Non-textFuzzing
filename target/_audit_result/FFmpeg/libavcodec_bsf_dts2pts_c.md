After a complete analysis of `dts2pts.c` with full context from related headers and implementations, here is my assessment:

**Systematic findings:**

1. **`offset_for_ref_frame` array copy** (lines 309–310): `poc_cycle_length` comes from `uint8_t num_ref_frames_in_pic_order_cnt_cycle` (CBS-validated 0–255), and both arrays are size 256. No OOB.

2. **`alloc_and_insert_node` loop** (line 156): `poc_diff` is at most 2 in H.264 paths (`FFMIN` of 1 or 2 against bitstream value) and always 1 in HEVC path. Loop is bounded.

3. **`cmp_insert` subtraction** (lines 110, 113): Raw `int` subtraction of `poc` values could theoretically overflow, but this is a correctness issue (wrong tree ordering), not memory corruption.

4. **HEVC re-keying loop** (lines 490–503): `tnode=NULL` is used to remove a node; after removal `tnode` is set to the freed `AVTreeNode`, which is then passed to the re-insert call. On collision, the orphaned AVTreeNode is correctly freed. No UAF or leak.

5. **Eviction loop null dereference** (lines 750–758): `stale` could theoretically be NULL if `nb_nodes` diverges from actual tree size, but the guard `s->nb_nodes > ...` makes this unreachable under normal operation.

6. **`video_delay << 1`** (line 196): Bounded by `max_num_ref_frames ≤ 16`, so no practical integer overflow.

7. **`gop` modulo** (lines 235, 474, 571): `s->fifo_size` is a compile-time constant (64 for H.264, 32 for HEVC), no division by zero or OOB array indexing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
