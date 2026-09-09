After thorough multi-pass analysis of `ulti.c` and its supporting codebook header, all memory-safety paths are clean:

- **Codebook index** (`case 2`, non-modifier): `tmp` is masked to 12 bits (max 4095), shifted left by 2 (max 16380), and accesses `tmp+0`…`tmp+3` (max 16383). The codebook is exactly 16384 bytes — last valid index is 16383. Tight but correct.
- **`ulti_lumas[64]` index**: Every luma value reaching `ulti_convert_yuv` is masked with `& 0x3F` (range 0–63) or comes from the codebook (all values confirmed 0–63). No OOB read.
- **`ulti_chromas[16]` index**: `chroma >> 4` and `chroma & 0xF` both yield 0–15. No OOB read.
- **Frame coordinate bounds**: `s->blocks = (width/8)*(height/8)`; the outer loop breaks on `blocks >= s->blocks || y >= s->height`; `x` and `y` are incremented only by multiples of 8, so the maximum subblock write at `(x+4, y+4)` writing 4×4 pixels always stays within the allocated frame buffer.
- **Bitstream reads**: Safe `bytestream2_get_byte/be16/be24` variants used throughout; unchecked `_u` variants appear only after explicit `bytestream2_get_bytes_left(…) < N` guards.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
