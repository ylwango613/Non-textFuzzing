Complete analysis summary:

- **`ff_dirac_init_arith_decoder` (line 96-123)**: `length` is clamped via `FFMIN(length, get_bits_left(gb)/8)` before use, and bytestream pointers are set correctly within valid buffer bounds.

- **`refill()` in dirac_arith.h (line 109-132)**: `bytestream_get_be16` is an unchecked read — if `bytestream_end - bytestream` is 0 or 1, it reads 1-2 bytes past `bytestream_end`. However, FFmpeg's universal `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) zero-padding guarantee on all input buffers makes this safe by design; the code then correctly patches the overread bytes to 0xff. This is intentional behavior documented in the comment.

- **`dirac_get_arith_bit` (context index)**: `c->contexts[ctx]` — `ctx` always comes from hardcoded enum values or `ff_dirac_next_ctx[]` table transitions, never from external input. All paths remain within `[0, DIRAC_CTX_COUNT)`.

- **`ff_dirac_prob_branchless[prob_zero>>8][bit]`**: `prob_zero` is `uint16_t`, so `>>8` yields [0,255]; `bit` is 0 or 1. Array is `[256][2]`. Fully bounded.

- **`dirac_get_arith_uint` overflow guard**: `ret >= 0x40000000` check before each `ret <<= 1` prevents signed overflow.

- **`dirac_get_arith_int` `data_ctx+1` use**: Callers use `CTX_COEFF_DATA` (14→15=CTX_SIGN_NEG), `CTX_DELTA_Q_DATA` (20→21=CTX_DELTA_Q_SIGN), `CTX_DC_DATA` (0→1) — all hardcoded, all in bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
