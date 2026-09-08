Now I have all the context I need. Let me verify the key sizes and call chains:

**Constants:**
- `LPC=50, NFRSZ=20, NONR=35, LPCLG=10, NONRLG=20, NUPDATE=4`
- `NSBSZ=105, NSBGSZ=34`

**`do_hybrid_window` stack buffers (g728dec.c instantiation):**
- `buffer1/buffer2[MAX_BACKWARD_FILTER_ORDER+1]` = `[51]`
- `work[FFALIGN(50+20+35,16)]` = `[112]`

**`vector_fmul(work, window, hist, FFALIGN(order+n+non_rec,16))`:**

For call with `order=LPC=50, n=NFRSZ=20, non_rec=NONR=35`:
- `len = FFALIGN(105,16) = 112`; `hist=s->sb` has only 105 floats → OOB read of 7 floats (reads into `sbg`)

For call with `order=LPCLG=10, n=NUPDATE=4, non_rec=NONRLG=20`:
- `len = FFALIGN(34,16) = 48`; `hist=s->sbg` has only 34 floats → OOB read of 14 floats (reads into `gp`)

For ra288.c: `sp_hist[111]` read with len=112 (1 over); `gain_hist[38]` read with len=48 (10 over).

**Exploitability assessment:**
- All OOB reads are **fixed-size** (not attacker-controllable — derived from compile-time constants)
- All reads stay **intra-struct** (same heap allocation, adjacent fields)
- No OOB **writes** anywhere in the template
- `order`, `n`, `non_rec` are hardcoded constants at every call site — no attacker can influence them via crafted media input
- `convolve()` accesses `work[0..110]` which is safely within `work[112]`
- The final loop `for(i=0; i<=order; i++)` writes to `buffer1[i]`/`buffer2[i]` which are exactly `[order+1]` sized

The OOB reads are latent undefined behavior (ASAN would flag them) but are not attacker-triggered, not cross-allocation, and produce no exploitable primitive.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
