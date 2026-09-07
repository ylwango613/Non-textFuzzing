The file is 294 lines. I've now read it completely and explored all calling contexts. Let me summarize the analysis:

**jpc_mct.c analysis (lines 1-294)**

- 5 functions: `jpc_rct`, `jpc_irct`, `jpc_ict`, `jpc_iict` (MCT transforms), `jpc_mct_getsynweight`
- No `malloc`/`realloc`/`calloc` or memory allocation calls
- No `memcpy`/`memmove` with size parameters from file fields
- No buffer size calculations

**Dimension mismatch (assert-only guards, lines 101-102, 145-146, 190-192, 231-232):**  
All four transform functions use `numrows`/`numcols` from `c0` and do raw pointer walks over `c1` and `c2`. Mismatched dimensions would cause OOB pointer arithmetic. However:
- In the decoder path (`jpc_dec.c:1130-1143`), `jas_image_cmpt_domains_same(dec->image)` guards the call — it checks that all components share the same `hstep_`, `vstep_`, `width_`, `height_`
- `dec->image->cmpts_[i]->hstep_` is populated from `dec->cmpts[compno].hstep` = `siz->comps[compno].hsamp` (same source used for tile data allocation at lines 737-740 in jpc_dec.c)
- If hstep/vstep are equal across components, `JPC_CEILDIV(tile->xend, cmpt->hstep)` is identical for all components → same tile matrix dimensions → no OOB

**No other exploitable vectors found:**
- `jpc_mct_getsynweight` is pure arithmetic, no memory accesses
- All arithmetic overflow in RCT/ICT is signed integer overflow (UB, not memory-safety)
- No NULL-deref: matrix allocation failures in jpc_dec.c return -1 before reaching MCT

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
