I have completed a full analysis of `common.c` (331 lines, read in one pass) with deep dives into all callsites and related headers. Here is the complete findings:

**Batch 1 (lines 1–331) — Analysis:**

**`getbits()` / `getbits_fast()` (lines 270–314):** Always reads 3 bytes (or 2 bytes for fast) from `wordpointer` without bounds checking. Potential OOB read past the end of `bsspace[bsnum]`. However:
- `bsspace` is `[2][MAXFRAMESIZE+512]` = `[2][2304]` bytes within `MPSTR`
- Over-reading `bsspace[0]` hits `bsspace[1]`; over-reading `bsspace[1]` hits `hybrid_block` — both are valid allocated struct memory within the same `MPSTR` heap/stack allocation
- Max OOB read is 1–2 bytes into adjacent struct fields; not exploitable for memory corruption

**`set_pointer()` (lines 317–331):** Guard `if(mp->fsizeold < 0 && backstep > 0)` uses AND, not OR. If `fsizeold=0` and `backstep=511`, code proceeds:
- `wordpointer -= 511`: result is `bsspace[bsnum]+512+ssize-511`. With min ssize=9, destination is `bsspace[bsnum]+10` — within bounds.
- `memcpy(src, bsbufold+0-511, 511)`: source is `bsspace[1-bsnum]+1` — within the 512-byte padding prefix. Protected by design.
- `main_data_begin` is 9-bit (max 511) ≤ the 512-byte padding ⇒ **not exploitable**

**`decode_header()` (lines 144–235):** All index expressions use bounded bitfield extractions; `fr->lsf` ∈ {0,1}, `fr->bitrate_index` ∈ 0–14, `fr->sampling_frequency` ∈ 0–8. No integer overflow in framesize calculation; maximum layer 3 framesize ≈ 1440 < MAXFRAMESIZE=1792.

**`print_header()` (lines 239–267):** `layers[fr->lay]` could OOB when `fr->lay=4`, but this function is only called from commented-out code (`/* print_header(fr); */` at line 232) — not in any execution path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
