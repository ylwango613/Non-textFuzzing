After fully reading `itut35.c` (404 lines), the header `itut35.h`, the sub-function `atsc_a53.c::ff_parse_a53_cc`, the `bytestream2_init` implementation, and all callers (`h2645_sei.c`, `libdav1d.c`, `av1dec.c`, `libaomdec.c`), my complete analysis is:

**Group 1 – `ff_itut_t35_parse_buffer` (lines 34–161):** All reads use `bytestream2_get_*u` / `bytestream2_skipu` functions that are preceded by explicit `bytestream2_get_bytes_left` guards. The final `payload`/`payload_size` pair is set atomically from the same bytestream context (lines 153–154), so they are always consistent and bounded by the original `buf_size`. No OOB reads.

**Group 2 – `ff_itut_t35_parse_payload_to_struct` (lines 163–320):**
- *AFD dereference* (line 186): `*itut_t35->payload` is accessed without re-checking `payload_size`, but all callers go through `ff_itut_t35_parse_buffer` first, which enforces `payload_size >= 1` at lines 150–151. Safe.
- *A53 CC narrowing* (line 190): `itut_t35->payload_size` (`size_t`) is passed to `ff_parse_a53_cc` which takes `int`. On a 64-bit host this is a narrowing conversion; however, the function immediately checks `if (size < 3)` (catching negative after wrap) and the subsequent `cc_count * 3 >= size - 3` check prevents any OOB read regardless of the truncated value. Not exploitable.
- *LCEVC memcpy* (lines 275–279): `av_buffer_alloc(payload_size)` allocates exactly `payload_size` bytes; `memcpy` copies exactly `payload_size` bytes from the same-sized source. Allocation and copy sizes are identical. No overflow.
- All other paths (HDR+, HDR Vivid, Dolby, SMPTE) delegate to sub-functions with their own internal size validation (`av_dynamic_hdr_plus_from_t35`, `ff_dovi_rpu_parse`, etc.).

**Group 3 – `ff_itut_t35_parse_payload_to_frame` (lines 322–391):** Pure dispatch; no direct memory operations beyond calling the functions already analysed.

**`bytestream2_init` narrowing:** `buf_size` is `size_t` but `bytestream2_init` accepts `int`. ITU-T T.35 payloads in real streams are always a few hundred bytes — far below `INT_MAX`. The `av_assert0(buf_size >= 0)` guards debug builds. Not practically exploitable.

No genuine, externally triggerable memory-safety vulnerability was found in this file or its direct call chain.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
