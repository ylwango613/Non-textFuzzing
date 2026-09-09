After thorough analysis of all relevant files, I have my conclusion.

**Analysis summary:**

- `roqvideo.c`: `block_copy` / `apply_motion_generic` — motion bounds check at lines 112-117 is correct for YUVJ444P (same-dimension UV planes). `boffs = y*stride + x` uses normal int arithmetic with frame-limited coordinates; no overflow at realistic dimensions.
- `ff_apply_vector_2x2/4x4` — no bounds checking locally, but callers maintain invariants: `xpos` always stays in `[0, width-16]`, so sub-block coordinates never reach out-of-frame pixels.
- `roqvideodec.c`: Codebook arrays `cb2x2[256]` / `cb4x4[256]` are statically sized; `bytestream2_get_byte` produces values 0-255 — no OOB indexing possible.
- `idroqdec.c`: `chunk_size = AV_RL32() + 16 + codebook_size` can unsigned-overflow, but the resulting undersized packet is only read via safe `bytestream2` APIs in the decoder, so no heap corruption path exists.
- Audio division `chunk_size / roq->audio_channels` — audio_channels is always 1 or 2 from channel layout macros; no divide-by-zero.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
