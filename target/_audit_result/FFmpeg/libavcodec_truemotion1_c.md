Both vulnerabilities are confirmed. Writing the final report now.

## VULN: OOB Heap Read via mb_change_bits in Interframe Decoding (No Size Validation)
- **漏洞类别**: memory-safety
- **函数**: truemotion1_decode_header() / truemotion1_decode_16bit() / truemotion1_decode_24bit()
- **行号**: 455-458 (missing check), 657 + 734 (16-bit OOB reads), 783 + 860 (24-bit OOB reads)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (TrueMotion 1 interframe)
- **外部触发路径**: `ffmpeg -i crafted.avi -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `truemotion1_decode_frame()` → `truemotion1_decode_header()` [missing interframe size check] → `truemotion1_decode_16bit()` or `truemotion1_decode_24bit()` [OOB reads of mb_change_bits]
- **描述**: In `truemotion1_decode_header()` (lines 450–459), for keyframes the code validates that enough packet bytes exist (line 453: `width * height / 2048 + header_size > s->size`). However, the interframe branch (else at line 455) performs **no equivalent validation**: it computes `s->index_stream = s->mb_change_bits + (s->mb_change_bits_row_size * (s->avctx->height >> 2))` and sets `s->index_stream_size = s->size - (s->index_stream - s->buf)` without checking whether the mb_change_bits region (`mb_change_bits_row_size * (height >> 2)` bytes) actually fits within the packet. In `truemotion1_decode_16bit()`, line 657 reads `mb_change_byte = mb_change_bits[mb_change_index++]` unconditionally each row, and line 734 reads an additional byte per 8 macro-blocks — both without bounds checking against `s->size`. For a crafted packet with large `width`/`height` but minimal data, the `mb_change_bits` pointer reads far beyond the end of the heap-allocated packet buffer (`AVPacket.data`).
- **触发条件**: Craft a TrueMotion 1 interframe (header byte with FLAGS_INTERFRAME set, header_type ≥ 2, flags bit-3 set) with large `xsize` (e.g. 65534) and `ysize` (e.g. 4), but provide only a minimal-length packet (e.g. 20 bytes). `mb_change_bits_row_size = ceil(65534/32) = 2048` bytes are needed for the change-bits region, yet the packet contains none. Deliver via an AVI container with the TrueMotion 1 codec FourCC `DUCK`/`PVEZ`.
- **安全影响**: Heap out-of-bounds read of up to `mb_change_bits_row_size * (height/4)` bytes (up to ~2 MB for maximum dimensions) beyond the allocated packet buffer. Causes immediate crash (SIGSEGV) if unmapped pages are reached → reliable DoS. On a successful read from adjacent heap allocations, `mb_change_byte` controls the decode/skip code path in the inner loop, and decoded pixel values (derived from predictor tables) are written to the output frame buffer — this creates a limited heap-data-disclosure vector through the output video frame.

## VULN: OOB Heap Read via Unconditional mb_change_bits Read in 24-bit Keyframe Path
- **漏洞类别**: memory-safety
- **函数**: truemotion1_decode_24bit()
- **行号**: 783 (unconditional read, missing keyframe guard)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted media file (TrueMotion 1 24-bit keyframe)
- **外部触发路径**: `ffmpeg -i crafted.avi -f null -` → `avcodec_send_packet()` → `truemotion1_decode_frame()` → `truemotion1_decode_header()` [compression → ALGO_RGB24H, FLAG_KEYFRAME set] → `truemotion1_decode_24bit()` [line 783 unconditional OOB read]
- **描述**: `truemotion1_decode_16bit()` correctly guards the per-row `mb_change_bits` read with `if (!keyframe)` at line 656. `truemotion1_decode_24bit()` lacks this guard: line 783 always executes `mb_change_byte = mb_change_bits[mb_change_index++]` regardless of whether the frame is a keyframe. For a 24-bit keyframe (`compression` ∈ {10,12,14,16} → `ALGO_RGB24H`), `s->mb_change_bits = s->buf + header_size` and `s->index_stream = s->mb_change_bits` (same pointer, line 452). The keyframe size check at line 453 only requires `width * height / 2048 + header_size ≤ s->size`. For small but valid dimensions (e.g. width=2, height=4), this evaluates to `0 + header_size ≤ s->size`, meaning a packet of `header_size + 1` bytes passes validation. However, `truemotion1_decode_24bit()` executes line 783 once per row (`height` = 4 iterations), reading `mb_change_bits[0]` through `mb_change_bits[3]` — yet only 1 byte exists after the header. Three of the four reads are heap OOB.
- **触发条件**: Craft a TrueMotion 1 packet with: `buf[0]` giving `header_size` ≥ 16 (e.g. 0x82 → header_size = 16), `compression` byte (header_buffer[0]) set to 10/12/14/16 (ALGO_RGB24H), `header_type ≥ 2` with no INTERFRAME flag (keyframe), `xsize=4` (`ysize=4`), and total packet length = `header_size + 1`. After XOR-decoding, the single trailing byte is the only valid data; the decode loop reads 4 bytes from `mb_change_bits`.
- **安全影响**: Heap out-of-bounds read of up to `height - 1` bytes past the packet allocation (e.g. 3 bytes for minimum height=4, scaling with height up to 65535 bytes). Causes crash (SIGSEGV) → DoS, or reads adjacent heap data into the `mb_change_byte` variable. Because `truemotion1_decode_24bit()` is a keyframe decoder, the `mb_change_byte` value does not affect the decode path (the `if (keyframe || ...)` condition at line 789 always takes the keyframe branch), so information disclosure through pixel output is limited; the primary impact is crash-based DoS.

<!-- AUDIT_PROMPT_VERSION: 1 -->
