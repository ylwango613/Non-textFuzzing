I've now completed a thorough analysis of the entire file and all relevant code paths. Here is my complete audit summary:

**File analyzed**: `libavcodec/bsf/av1_frame_split.c` (262 lines)

**Key findings from analysis:**

1. **`int size` vs `size_t data_size` (lines 92, 97)**: `size` is `int` but `unit->data_size` is `size_t`. However, CBS OBU data sizes are bounded by the packet size (which itself is `int`), so practical overflow cannot occur.

2. **NULL deref via EAGAIN-dropped OBU**: If an AV1 FRAME OBU has `obu_extension_flag` set and is dropped by the operating-point-IDC filter returning `AVERROR(EAGAIN)`, its `unit->content` becomes NULL. The frame-counting loop (lines 71–81) still counts it based on `unit->type`, but the split block at line 99 dereferences `unit->content` → crash. This is a DoS (SIGSEGV), **not memory corruption**.

3. **`tile_cols * tile_rows` on line 148**: Both are `uint16_t` (max 64 each, enforced by CBS parsing via `AV1_MAX_TILE_COLS = 64`), so `64 * 64 = 4096` — no overflow.

4. **Buffer pointer arithmetic (lines 167–168)**: `s->buffer_pkt->data += size; s->buffer_pkt->size -= size;` is bounded by CBS guarantees that the sum of unit `data_size` values equals the packet size.

5. **CBS unit `data_ref` ownership**: Units hold references to the original packet buffer via `frag->data_ref`, so the `ff_cbs_fragment_reset` at line 175 correctly cleans up without leaving dangling pointers in the output packet.

No exploitable heap overflow, use-after-free, out-of-bounds write, or other memory corruption vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
