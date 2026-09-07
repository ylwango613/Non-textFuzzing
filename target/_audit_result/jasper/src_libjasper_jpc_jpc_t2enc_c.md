Having read all 667 lines of jpc_t2enc.c in batches and traced the complete call graph:

- `jpc_enc_encpkts`, `jpc_enc_encpkt`, `jpc_save_t2state`, `jpc_restore_t2state`, `jpc_init_t2state`, and `jpc_enc_pi_create` are all **encoder-only** functions, called exclusively from `jpc_enc.c` (the JPEG-2000 encoder).
- `imginfo` calls only `jas_image_decode`, which invokes the decoder path (`jpc_dec.c`, `jpc_t2dec.c`). None of the functions in `jpc_t2enc.c` appear anywhere in `jpc_dec.c` or in `imginfo.c`.
- Allocations in `jpc_enc_pi_create` (lines 580, 592, 606) all use `jas_alloc2`, which internally calls `jas_safe_size_mul` — overflow-safe by design.
- `jpc_bitstream_putbits` (called at line 325) explicitly rejects `n >= 32`, turning potential numlenbits overflow into a controlled EOF return rather than memory corruption.
- `jas_stream_copy` at line 385 uses a signed int count; if negative it copies until EOF, but this path is encoder-internal state and not reachable from a crafted input file via imginfo.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
