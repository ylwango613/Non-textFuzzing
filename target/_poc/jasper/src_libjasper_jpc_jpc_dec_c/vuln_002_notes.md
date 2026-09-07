# VULN-002 PoC Notes — `jpc_dec_process_siz()` Missing Return on Overflow

## Vulnerability Location

**File**: `src/libjasper/jpc/jpc_dec.c`  
**Function**: `jpc_dec_process_siz()`  
**Lines**: 1282–1284

```c
if (!jas_safe_size_add(num_samples, num_samples_delta, &num_samples)) {
    jas_eprintf("image too large\n");
    /* BUG: missing return -1 */
}
```

Immediately after this block, the guard at line 1287 is:

```c
if (dec->max_samples > 0 && num_samples > dec->max_samples) {
    ...
    return -1;
}
```

With `dec->max_samples == 0` (disabled via `--max-samples 0`), this guard is
always false, so both protections fail together.

## Root Cause

The missing `return -1` after the `jas_safe_size_add` failure means the decoder
continues with `num_samples` holding an undefined/wrapped value (the result of
the overflowed addition). In the default configuration the `max_samples > 0`
guard still fires and limits damage; but when the limit is disabled the decoder
proceeds to set up tile structures and eventually attempt image allocation using
component dimensions that were never validated for their aggregate size.

## Trigger Strategy

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `Csiz` | 16384 (0x4000) | Maximum allowed components per JPEG-2000 spec |
| Width (`Xsiz`) | 2^26 = 67,108,864 | Large enough to force cumulative overflow |
| Height (`Ysiz`) | 2^26 = 67,108,864 | Same |
| Per-component samples | 2^52 | Does NOT overflow `jas_safe_size_mul` (< 2^64) |
| Cumulative overflow | After ~4,096 components | 4096 × 2^52 = 2^64 > SIZE_MAX |

The per-component size (2^52) is deliberately chosen so that `jas_safe_size_mul`
at line 1278 succeeds (returning -1 there would mask the bug at 1282). The
overflow only appears in the cumulative addition.

## File Structure

```
JP2 Signature Box   (12 bytes)
File Type Box       (20 bytes)
JP2 Header Box      (jp2h superbox)
  Image Header Box  (ihdr, 22 bytes) — placeholder dims, real dims in SIZ
  Color Spec Box    (colr, 15 bytes)
Codestream Box      (jp2c, length=0 = extends to EOF)
  SOC  0xFF4F
  SIZ  0xFF51 — Csiz=16384, Xsiz=Ysiz=2^26, one tile, 3 bytes/component
  EOC  0xFFD9
```

SIZ marker payload: 2 + 36 + 3×16384 = **49,190 bytes** (fits in 2-byte Lsiz field).

## Invocation

```bash
imginfo --max-samples 0 -f vuln_002.jp2
```

The `--max-samples 0` flag sets `max_samples_valid=true` and passes
`max_samples=0` to the JPC decoder options parser, which sets
`dec->max_samples = 0`, disabling the sample-count limit check.

## Expected Behaviour

1. `jpc_dec_process_siz()` iterates over 16,384 components.
2. Around component 4,097 the cumulative `num_samples` addition overflows
   `size_t`. `jas_safe_size_add` returns false, an error is printed, but
   **execution continues** (the bug).
3. With `dec->max_samples == 0`, the subsequent guard is skipped.
4. The decoder proceeds to allocate tile/image structures for 16,384 components
   of 2^26 × 2^26 pixels — an astronomically large allocation.
5. Outcome: out-of-memory failure, abort, or (with ASAN instrumentation) an
   allocation-size overflow error.

## Impact Assessment

- **Default mode** (max_samples = 64 M): Low impact — the `max_samples > 0`
  guard fires on the first component whose size exceeds 64 M and returns -1
  before the missing-return bug is reachable.
- **--max-samples 0 mode**: Medium impact — an attacker-controlled JP2 file can
  force the decoder into an undefined state with a corrupted sample count,
  potentially causing OOM, process crash, or (in hardened builds) an ASAN abort.
  Resource exhaustion (DoS) is the primary risk.

## Fix

Add `return -1;` after the `jas_eprintf` call on line 1283:

```c
if (!jas_safe_size_add(num_samples, num_samples_delta, &num_samples)) {
    jas_eprintf("image too large\n");
    return -1;   /* <-- add this */
}
```
