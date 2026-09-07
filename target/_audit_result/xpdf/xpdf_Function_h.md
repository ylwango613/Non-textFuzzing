After exhaustive multi-pass analysis of Function.h and Function.cc, I have completed my review. Here is my complete analysis summary for each area:

**SampledFunction**: `m` capped at 16 (sampledFuncMaxInputs), `n` capped at 32. `nSamples` overflow check on line 358 (`nSamples > INT_MAX / sampleSize[i]`) is correct. The `samples[idx0 + idxOffset[j] + i]` access in `transform()` is mathematically bounded to [0, nSamples-1]. `gmallocn` itself checks `nObjs < 0 || nObjs >= INT_MAX / objSize` → calls `gMemError` (exit/throw), preventing any heap corruption.

**PostScriptFunction exec()**: All 43 opcodes have stack bounds checks before accessing `stack[]`. `sp` cannot go below 0 (psOpPush/psOpDup/psOpFalse/psOpTrue all check `sp < 1`). Jump targets (`c->val.i`) are set by the parser to positions in [0, codeLen] — always valid. `psOpIndex` with k=psStackSize is caught by the `sp + 1 + k >= psStackSize` underflow check.

**addCode codeSize doubling**: `codeSize *= 2` can overflow to INT_MIN after ~2^30 entries (requires billions of tokens — impractical). Even if triggered, `greallocn` checks `nObjs < 0` → `gMemError` → abort. No heap corruption.

**StitchingFunction**: `2 * k` signed overflow for enormous k is caught by `gmallocn`'s `nObjs < 0` check; abort, not corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
