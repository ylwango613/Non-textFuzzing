# VULN 001 - JasPer jpc_dec_tileinit() prcwidthexpn=0 UB / Assertion Failure

## Summary

A crafted JP2/JPEG-2000 codestream with a COD marker that enables per-precinct sizes
(Scod bit0=1) and sets the precinct-size byte for a non-LL resolution level to 0x00
triggers undefined behavior and an assertion failure in `jpc_dec_tileinit()`.

## Affected Code

**File:** `src/libjasper/jpc/jpc_dec.c`
**Function:** `jpc_dec_tileinit()`
**Key lines:**

```c
// Line 798-799
rlvl->cbgwidthexpn  = rlvl->prcwidthexpn - 1;   // => -1 when prcwidthexpn==0
rlvl->cbgheightexpn = rlvl->prcheightexpn - 1;  // => -1

// Line 851 (later, in the precinct loop)
cbgxend = cbgxstart + (1 << rlvl->cbgwidthexpn);  // 1 << -1 = UB
```

When `prcwidthexpn=0` for `rlvlno != 0`, subtracting 1 yields -1.
Shifting by a negative amount (`1 << -1`) is undefined behavior in C.
Additionally the computed precinct/cblk dimensions become zero or wrap,
leading to `jpc_tagtree_create(0, 0)` which hits an assertion:
```
assert(prc->numcblks > 0);
```

## Trigger Mechanism

1. **COD marker** with `Scod = 0x01` (bit 0 = 1 enables per-precinct size list).
2. `numdlvls = 1` => 2 resolution levels (rlvlno=0 LL, rlvlno=1 non-LL).
3. `prcsize[0] = 0x22`: rlvlno=0 (LL), PPy=2, PPx=2, `prcwidthexpn=2` (safe).
4. `prcsize[1] = 0x00`: rlvlno=1 (non-LL), PPy=0, PPx=0, `prcwidthexpn=0` => **TRIGGER**.

In `jpc_dec.c` line 763:
```c
rlvl->prcwidthexpn = ccp->prcwidthexpns[rlvlno];  // = 0 for rlvlno=1
```

Then at line 798:
```c
rlvl->cbgwidthexpn = rlvl->prcwidthexpn - 1;  // = -1 => UB cascade
```

## Proof-of-Concept

- **Generator:** `vuln_001_gen.py` - builds a minimal 4x4 1-component JP2 file.
- **Input:** `vuln_001.jp2` - crafted codestream embedding the trigger COD marker.
- **Tested with:** `imginfo` (JasPer's image-info utility).

## Impact

- Undefined behavior (signed integer left-shift by negative amount) per C11 §6.5.7.
- Potential assertion failure: `assert(prc->numcblks > 0)` in `jpc_dec_tileinit()`.
- With optimized/non-debug builds: heap write via `jas_alloc2(0, ...)` or
  `jpc_tagtree_create(0, 0)` returning/writing to a zero-size allocation.
- Exploitability: DoS at minimum; possible heap corruption with crafted input.

## Fix

Check `prcwidthexpn >= 1` before the subtraction for `rlvlno != 0`:
```c
if (rlvlno != 0 && rlvl->prcwidthexpn < 1) {
    /* invalid precinct size; reject tile */
    return -1;
}
rlvl->cbgwidthexpn = rlvl->prcwidthexpn - 1;
```
