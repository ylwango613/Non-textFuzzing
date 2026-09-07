I've now read all 2400 lines of emitter.c across 5 batches and analyzed the full context from yaml_private.h. Let me record my batch-by-batch findings before issuing the final verdict.

**Batch 1 (lines 1–500): Macros and state machine infrastructure**
- `FLUSH` guarantees `pointer + 5 < end` (≥ 6 free bytes) before each write; if not, it calls `yaml_emitter_flush` to drain to output.
- `PUT` writes 1 byte after FLUSH — safe.
- `PUT_BREAK` writes ≤ 2 bytes (CRLN) after FLUSH — safe.
- `WRITE` copies 1 byte via COPY after FLUSH — safe.
- `WRITEN` copies `n` bytes via `memcpy` after FLUSH — `n = utf8_width()` ≤ 4 < 6 — safe.
- `PUSH/ENQUEUE` call `yaml_stack_extend` / `yaml_queue_extend` on full; no fixed overflow.

**Batch 2 (lines 500–1000): State handlers**
All flow through PUSH, POP, and the write helpers — all guarded by FLUSH or dynamic realloc.

**Batch 3 (lines 1000–1500): Checkers, analyzers, `yaml_emitter_analyze_scalar`**
- `IS_BLANKZ_AT(string, 1)` is called when `string.pointer` points to the last 1-byte character (e.g., `:`). In that case `string.pointer[1]` = `string.end[0]` = NUL byte (libyaml allocates `length+1` and NUL-terminates). The multi-byte sub-checks (for 0xC2, 0xE2) short-circuit on NUL — no memory access past the allocation.
- `utf8_width()` correctly bounds-checks all multi-byte sequences before `IS_PRINTABLE` accesses them — no OOB read.
- No malloc calls with externally-controlled size in these paths.

**Batch 4 (lines 1500–2000): `utf8_width`, scalar analyzers, single/double quoted writers**
- `utf8_width` validates `end-pointer >= N` before returning N — correctly prevents OOB access in all callers.
- `yaml_emitter_write_double_quoted_scalar`: `WRITEN(emitter, string, width)` — after FLUSH (≥6 free bytes) copies ≤4 bytes — safe.
- `yaml_emitter_write_single_quoted_scalar`: all operations use PUT/WRITE after FLUSH — safe.

**Batch 5 (lines 2000–2400): Block/folded scalar writers, tag content writer**
- `yaml_emitter_write_tag_content`: %-encoding path calls 3 sequential PUTs, each with its own FLUSH re-check — safe.
- `yaml_emitter_write_bom`: FLUSH then writes 3 bytes — 3 < 6 guaranteed free — safe.
- Block/folded writers: only WRITE/PUT_BREAK/WRITE_BREAK after FLUSH — all safe.

**Cross-cutting analysis: attack reachability**
emitter.c is a YAML _output_ formatter. The scalar values it receives have already been parsed by flvmeta's FLV/AMF layer. No raw FLV file bytes flow directly into malloc size expressions, array indices, or buffer destination sizes inside this file. All output buffer management is protected by the FLUSH lazy-drain mechanism.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
