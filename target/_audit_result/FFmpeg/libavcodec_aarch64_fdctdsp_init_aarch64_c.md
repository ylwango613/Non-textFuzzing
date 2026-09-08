The file is 39 lines: a pure CPU-dispatch init function that assigns a function pointer (`c->fdct = ff_fdct_neon`) based on CPU flags and `avctx->dct_algo`. No allocations, no buffer operations, no size arithmetic, no user-controlled indexing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
