I've now read the entire 216-line file and traced all memory operations thoroughly. Here is my analysis summary before the final verdict:

**`eightsvx_decode_frame` (lines 90–156):**
- `chan_size = avpkt->size / channels - hdr_size` is computed before the size guard, but the guard at line 106 returns `AVERROR_INVALIDDATA` before any memory operation, so `chan_size` is always ≥ 1 when used.
- Both `memcpy` calls (lines 125, 127) copy exactly `chan_size` bytes into `av_malloc(chan_size)` buffers and read at most `avpkt->size - 1` from the packet — within bounds for all valid packet sizes.
- Stereo `fib_acc[1]` access (`avpkt->data[2+chan_size+1]`) resolves to `avpkt->data[avpkt->size/2 + 1]`; since `avpkt->size ≥ 6` for stereo, index is always valid.

**`delta_decode` (lines 73–87):**
- Table indices use `d & 0xF` (0–15) and `d >> 4` (0–15) — both 16-element tables are never overindexed.
- Writes exactly `2 * src_size` bytes; the caller allocates `frame->nb_samples = buf_size * 2` bytes per channel (U8P, 1 byte/sample) — exact fit, no overflow.

**`fib_acc[2]` array:** `ch` is bounded to [0, channels-1] where channels ≤ 2 — no OOB.

**Integer arithmetic:** `buf_size` is capped at `MAX_FRAME_SIZE = 2048`, so `nb_samples = 4096` — no overflow in `ff_get_buffer`.

After exhaustive analysis of all memory operations, size calculations, array accesses, and data-flow from untrusted packet data through the decode path, no exploitable memory-safety vulnerability was found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
