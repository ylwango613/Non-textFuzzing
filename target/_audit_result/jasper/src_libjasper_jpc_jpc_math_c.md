**Analysis summary:**

`jpc_math.c` (122 lines) contains exactly two functions:

**`jpc_floorlog2(int x)` (lines 89–102):** Pure bit-shift loop, no memory operations. `assert(x > 0)` is the only guard — assert-only failure, explicitly out of scope.

**`jpc_firstone(int x)` (lines 108–121):** Pure bit-shift loop, no memory operations. `assert(x >= 0)` guard — same exclusion applies. `jpc_firstone(0)` returns −1 legitimately.

**Macros in `jpc_math.h`:**
- `JPC_CEILDIVPOW2(x, y)` = `((x) + (1 << (y)) - 1) >> (y)` — arithmetic UB if y≥31, but no memory ops in the macro itself; all call sites in `jpc_qmfb.c`/`jpc_tsfb.c` pass literal `1` as y, so no shift UB.
- `JPC_FLOORDIVPOW2(x, y)` — used in `jpc_t2cod.c` with file-controlled `prcwidthexpn` as shift amount (possible UB), but still no memory operation inside the macro.
- `JPC_CEILDIV(x, y)` — integer overflow possible but no memory op.

**Caller chain check:** `jpc_floorlog2(n)` in `jpc_t2dec.c:314` is gated by `n = JAS_MIN(numnewpasses, maxpasses)` which must be ≥1 to reach that call; `jpc_firstone` results in encoding paths are irrelevant to the `imginfo` decoder attack surface; `JPC_CEILDIVPOW2(numcols, 1)` in `jpc_qmfb.c` feeds `bufsize` which gates heap vs. stack allocation — the stack buffer `splitbuf[QMFB_SPLITBUFSIZE]` is only used when `bufsize ≤ QMFB_SPLITBUFSIZE`, and since `bufsize ≈ numcols/2` and `m ≈ numcols/2`, no stack overflow is reachable through the normal integer range without the decoder first failing to allocate the tile buffer.

Neither function in `jpc_math.c` performs any memory allocation, pointer arithmetic, or buffer access. No memory safety vulnerability is directly attributable to this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
