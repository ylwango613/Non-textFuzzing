Having thoroughly analyzed the complete 227-line file, I traced every memory access path:

**Header check (line 67):** The minimum size check `FRAME_HEADER_SIZE + avctx->height * 3` could theoretically overflow if height > ~715M, but FFmpeg's codec layer caps dimensions well before this.

**linelength=0 edge case (line 122):** `src[linelength - 1]` with `linelength = 0` → `uint16_t` promotes to `int`, giving `src[-1]`. However, at that point `src` has been advanced by at least `FRAME_HEADER_SIZE + 2 = 66` bytes into the packet, and the header check guarantees `avpkt->size >= FRAME_HEADER_SIZE + height*3 ≥ 67` bytes for height ≥ 1. So `src[-1]` always lands within the allocated packet buffer — this is a logical oddity (reads the wrong byte), not an OOB memory access.

**Output buffer writes (lines 143–183):** Both inner decode loops — odd-line Y-only (lines 142–157) and even-line YUV (lines 162–183) — check `y > y_end` / `y+1 > y_end || u > u_end || v > v_end` at the TOP of each iteration before any write or skip. A compressed skip can advance `y` past `y_end`, but the NEXT iteration catches this before any write occurs.

**src bounds in inner loops:** The `src_size < linelength` check (line 117) fires before accessing `src[0..linelength-1]`. Even-line mode accesses `src[j+3]` with `j < linelength - 4`, so max access is `src[linelength-2]` — within bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
