Based on full analysis of `psymodel.c` (86 lines), `psymodel.h`, and their call chains:

**Batch 1 — allocation and init loop (lines 35–54)**
- `ctx->ch` allocated as `nb_channels * 2` elements (line 35); guarded by NULL check at line 41 before the loop.
- `ctx->group[i].num_ch = group_map[i] + 1` (line 52). `FFPsyChannelGroup.ch` has `PSY_MAX_CHANS = 20` slots; the inner loop writes `num_ch * 2` pointers. An overflow would require `group_map[i] >= 10`. The sole real caller (`aacenc.c` line 1887) computes `grouping[i] = s->chan_map[i+1] == TYPE_CPE` — always 0 or 1 — so `num_ch` is always 1 or 2; the `ch[]` array is never overrun in practice.

**Batch 2 — `ff_psy_find_group` (lines 67–75)**
- The `while (ch <= channel)` loop has no upper bound on `i` against `ctx->num_groups`. If `channel` ≥ total allocated channels, `ctx->group[i].num_ch` is read past the heap allocation. However, `channel` is supplied exclusively by the AAC encoder's own internal channel-element index, not by any crafted bitstream field.

**Batch 3 — attack surface assessment**
- This file is **encoder-only** (psychoacoustic model for AAC encoder). It processes pre-filtered data from the encoder's own channel map, not raw container or bitstream bytes.
- No field in `psymodel.c` is read from an untrusted media file; all sizing/indexing parameters originate inside the encoder's initialization logic (`aacenc.c`), which constrains values well within safe bounds.
- A crafted input file influences only the audio PCM samples passed to the encoder — not the structural parameters (`num_groups`, `group_map`, `channel` index) that govern memory allocation and array indexing here.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
