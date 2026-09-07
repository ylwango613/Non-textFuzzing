All lookup-table bounds checked: `jpc_zcctxnolut[4*256]` max index = `(3<<8)|255 = 1023`, `jpc_spblut[256]` max index 255, `jpc_scctxnolut[256]` max index 255, `jpc_magctxnolut[4096]` max index `(1<<11)+2047 = 4095`. All within bounds. `band->orient` is always assigned from `JPC_TSFB_LL/LH/HL/HH` constants (0–3), not from file data, so the LUT index `orient<<8` is bounded to 768. The flags matrix is allocated with +2 rows and +2 cols, giving a valid 1-element border for all `UPDATEFLAGS4` neighbor accesses (`fp[-1]`, `fp[1]`, `np[-1]`, `np[1]`). No malloc/realloc calls in the file. No externally-controlled parameters reach the LUT indices or array writes in `jpc_t1cod.c`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
