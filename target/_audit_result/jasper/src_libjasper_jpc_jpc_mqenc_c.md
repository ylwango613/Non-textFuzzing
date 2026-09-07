The `jpc_mqenc.c` module implements the MQ arithmetic *encoder*. `imginfo` only *decodes* images — it uses `jpc_dec.c`/`jpc_t1dec.c`/`jpc_mqdec.c`. The grep confirms `jpc_mqenc` is referenced only by `jpc_enc.c` and `jpc_t1enc.c` (encoding modules), never by any decode path.

All internal operations (context indices via `jpc_mqenc_setcurctx`, `maxctxs` via `JPC_NUMCTXS`) use compile-time constants, not file-supplied data. No file-controlled values feed into malloc sizes or array indices in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
