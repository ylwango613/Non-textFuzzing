After thorough analysis of all relevant files — `h264qpel.c`, `h264qpel_template.c`, `util_altivec.h`, and `hpeldsp_altivec.h` — here is the full assessment:

**Key findings:**

- All buffer sizes in `H264_MC` macro are compile-time constants (`SIZE=16` always for the altivec variant): `half[256]`, `tmp[384 int16_t = 768 bytes]`, `halfH/halfV/halfHV[256]` — no user-controlled sizing.
- `hv_lowpass_altivec`: first loop writes 21×32=672 bytes into `tmp`; second loop reads the same; 768-byte buffer is sufficient.
- `avg_unligned_store` macro uses `dst` instead of the `dest` parameter (a typo bug), but the only call site is `avg_unligned_store(d, dst)` so the parameter equals the outer variable — no corruption.
- `put_pixels16_l2_altivec`/`avg_pixels16_l2_altivec`: stride (`src_stride1`) and loop count (`h=16`) come from decoder frame allocation, not directly from the bitstream.
- `v_lowpass` reads `src - (srcStride * 2)`, which is standard H.264 border-pixel assumption, not an external size field.
- No `av_malloc`/`av_realloc`/`memcpy` calls with attacker-controlled sizes anywhere in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
