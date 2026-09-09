I have now read the full file (314 lines) and traced all key call chains: `build_vlc`, `get_tree_codes`, the LZVY inflation path, and the HUFY VLC-decode path. Here is my analysis summary before the final output:

**`build_vlc` — `nodes[512]` bounds:**
With `nb_symbols ≤ 256`, the Huffman tree has at most 255 internal nodes → `cur_node_max = 255 + 255 = 510`. Index 510 and the sentinel probe at 511 are both within `nodes[512]`. The algorithm correctly detects the single-root termination via the `first_node == cur_node` break before `cur_node` could reach 512.

**`s->symb[i]` / `s->prob[i]` array indexing:**
`s->nb_symbols = get_bits(gb,8)+1` → max 256. `symb[256]` and `prob[256]` → indices 0–255 are legal. The loop increments `i` only when `prob != 0`; if bits run out before filling all nb_symbols entries, `AVERROR_INVALIDDATA` is returned before `build_vlc` is called.

**`get_tree_codes` — `bits[256]`/`lens[256]`/`xlat[256]`:**
`*pos` is incremented once per leaf. Max leaves = nb_symbols ≤ 256, so `*pos` can reach at most 255 before the final leaf is written → indices 0–255 used; no OOB.

**LZVY zlib inflation:**
`avail_out = avctx->width >> (p > 0)` is bounded by the allocated frame row size. The `avpkt->size > 8` pre-check ensures `avpkt->size - 8 ≥ 1` for `avail_in`. No OOB.

**Prediction loop (`add_left_pred` / `add_median_pred`):**
`dst` walks bottom-up; `dst + stride` is the already-decoded row below. After the final inner iteration, `dst` goes to `frame->data[p] - stride` but is never dereferenced. No OOB.

**Integer overflow at `get_bits_left(gb) < avctx->height * avctx->width` (line 223):**
If height and width are both large enough to overflow `int`, the per-row check at line 241 (`get_bits_left(gb) < width`) catches shortfall before any write to `dst[x]`. No reachable OOB write path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
