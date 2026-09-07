I have now read the complete `avc.c` file (262 lines), all relevant headers (`avc.h`, `bitstream.h`, `types.h`, `flv.h`), the bit-manipulation implementation (`bitstream.c`), and traced the full call chain through `info.c` and `flv.c`. Let me document my analysis:

**Group 1 – `read_avc_resolution()` (lines 197-261)**

- `sps_size` is `uint16` (max 65535). `malloc((size_t)sps_size)` cannot overflow `size_t`.  
- The guard at line 241 (`sps_size == 0`) prevents zero-size allocation.  
- The bounds check `sps_size > body_length - 12` at line 242 can unsigned-underflow if `body_length < 12`. However, because the initial check at line 205 only requires `body_length >= 10`, values of 10 or 11 pass through. Analysis: when `body_length = 10-11`, the prior reads (1+3+6 bytes) consume exactly the available body bytes; the `flv_read_tag_body` call at line 235 for `sps_size` then returns 0-1 bytes < 2, causing early return at line 236. The underflow line 242 is thus never reached with `body_length < 12`. Confirmed by `flv_read_tag_body()` (flv.c:341): it limits reads to `min(buffer_size, stream->current_tag_body_length)`.
- The `flv_read_tag_body(f, sps_buffer, (size_t)sps_size)` call writes at most `sps_size` bytes into a `sps_size`-byte buffer – no overflow possible.

**Group 2 – `parse_sps()` (lines 74-191)**

- All bit reads go through `get_bit()` which checks `bb->current - bb->start > bb->size - 1` before every dereference. Returns `-1` on OOB; all callers in `parse_sps` check for `-1` and return.
- `skip_bits()` advances the pointer without bounds checking, but the pointer is never dereferenced until the next `get_bit()` call, which bounds-checks first.
- The loop `for (i = 0; i < size; i++) { exp_golomb_se(&bb); }` (line 144) with a large `size` from Exp-Golomb decoding causes slow looping but no memory corruption – once the bit buffer is exhausted, `get_bit()` returns `-1` immediately.

**Group 3 – `exp_golomb_ue()` in bitstream.c**

- `(1 << significant_bits)` is UB when `significant_bits >= 32` (uint8 can reach up to 255), but this only produces an incorrect Golomb value. No memory operation depends on this value in a way that could cause corruption.

**Conclusion:** No memory-safety vulnerability (heap overflow, OOB write/read, integer overflow leading to under-allocation) is present in `avc.c` or its direct callees as exercised from this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
