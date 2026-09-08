After thorough analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/cabac.c` (188 lines) and its companion headers `cabac.h` and `cabac_functions.h`, including tracing all call sites in H.264, HEVC, and VVC decoders:

**Findings summary:**

1. `ff_init_cabac_decoder` reads `buf[0]` and `buf[1]` (and conditionally `buf[2]`) with CABAC_BITS==16 before checking `buf_size` — a technical OOB read if `buf_size < 2`. However, all call sites pass buffers that are part of AVPacket data, which carries FFmpeg's mandatory `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) of trailing padding. The reads are into guaranteed padding bytes and cannot reach unmapped memory.

2. `refill()` and `refill2()` in `cabac_functions.h` read `bytestream[0]` and `bytestream[1]` unconditionally when the pointer is at `bytestream_end`. The bounds check only guards the pointer *advance*, not the *read*. This is an intentional design pattern (documented to require AV_INPUT_BUFFER_PADDING_SIZE) and not independently exploitable.

3. No heap allocations, no memcpy with attacker-controlled sizes, no integer overflow → underalloc patterns exist in this file.

4. The `skip_bytes` `(int)(bytestream_end - ptr)` cast is not exploitable for practical media file sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
