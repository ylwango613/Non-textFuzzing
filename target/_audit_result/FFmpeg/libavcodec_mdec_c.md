After thorough analysis of all 262 lines in `mdec.c` — including the decode loop, quantization arithmetic, bitstream reading, frame writes, and size checks — and examining the related `bswapdsp.h` signature (`bswap16_buf` takes `int len`), here is my final assessment:

**Group 1 — `decode_init` (lines 217-218):** `mb_width/mb_height = (coded_{width,height} + 15) / 16`. The `+15` can technically overflow for INT_MAX inputs, but FFmpeg validates dimensions before reaching the decoder.

**Group 2 — `decode_frame` size check (line 177):** `a->mb_width * a->mb_height * 3` is signed-int multiplication and can overflow, making the guard return a negative value that bypasses the check. However, when the product is large enough to overflow, the corresponding frame dimensions would require gigabytes of memory that `ff_thread_get_buffer` fails to allocate, causing an early error return — so no actual memory write occurs.

**Group 3 — `bswap16_buf` count (line 186):** For odd `buf_size`, `(buf_size + 1) / 2` processes one extra byte from `buf`. The extra byte falls within AVPacket's `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) padded region — no true OOB read.

**Group 4 — `idct_put` frame writes (lines 154-156):** `mb_y * 16 * linesize` can overflow 32-bit int for extreme dimensions, but such extreme dimensions prevent successful frame allocation.

**Group 5 — block index `i` (lines 92, 108):** Explicitly checked against 63 before use as array index — no OOB.

**Group 6 — quantization arithmetic (lines 98, 116, 120):** Integer overflow is possible in `level * qscale * quant_matrix[j]` since `qscale` is attacker-controlled up to 65535. This is C signed integer overflow (UB), but the result is only written to `block[j]` — a correctly bounded array — so this is a value-corruption bug, not a memory-safety bug.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
