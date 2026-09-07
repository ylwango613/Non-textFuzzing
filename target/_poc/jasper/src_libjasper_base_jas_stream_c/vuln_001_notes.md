# VULN 001 – mem_seek Dead Unsigned Check (CWE-191)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| ID | VULN 001 |
| CWE | CWE-191 – Integer Underflow (Unsigned Wrap-around) |
| File | `src/libjasper/base/jas_stream.c` |
| Function | `mem_seek()` |
| Lines | 1267–1293 |
| Status | UNVERIFIED – present in source, not triggerable via imginfo + JP2 path |

## Root Cause

`mem_seek()` declares `newpos` as `size_t` (unsigned):

```c
size_t newpos;
newpos = (size_t)(offset + m->pos_);   // SEEK_CUR
// or
newpos = (size_t)(offset);             // SEEK_SET
```

The subsequent guard at line 1287 is dead code:

```c
if (newpos < 0) {          // LINE 1287 — ALWAYS FALSE for size_t
    return -1;
}
```

Because `size_t` is unsigned, `newpos < 0` is always false. The compiler
eliminates this branch entirely. When a SEEK_SET offset exceeds `m->len_`,
the error return is bypassed and `m->pos_` is silently set past the stream end.
A subsequent `mem_read()` computes `n = m->len_ - m->pos_`, which as a signed
subtraction wraps to a large positive value, resulting in a heap-buffer-overflow.

## Why the Vulnerability Is Not Triggerable via `imginfo + JP2`

Three reasons together prevent OOB access through this path:

1. **Stream allocation matches seek distance.** `jas_image_cmpt_create()` calls
   `jas_stream_memopen2(0, size)` where `size = width * height * depth`, then
   immediately seeks to `size - 1` (to pre-extend the buffer). The stream's
   `bufsize_` equals `size`, so `newpos = size - 1 < bufsize_`. The seek is
   always in-bounds.

2. **Subsequent write calls are bounds-checked.** `jas_image_writecmpt()` checks
   `if (x >= cmpt->width_ || y >= cmpt->height_ || ...)` before computing any
   seek offset, preventing caller-supplied out-of-range coordinates from
   reaching `mem_seek`.

3. **Seek offsets are derived from image dimensions.** All SEEK_SET calls on
   component streams use coordinates bounded by the image's own width/height,
   which are the same values used to size the stream. There is no code path
   that passes a file-controlled arbitrary value directly to `jas_stream_seek`
   on a component stream.

## Root Cause of Earlier Variant Failures (v1–v4)

All earlier variants produced `"cannot get marker segment"` before tile
decoding was reached. Two compounding bugs:

### Bug 1: Psot=0 rejected by `jpc_sot_getparms`

`jpc_cs.c` lines 439–442:

```c
if (sot->tileno > 65534 || sot->len < 12 || sot->partno > 254 ||
    sot->numparts < 1 || sot->numparts > 255) {
    return -1;
}
```

`sot->len` is the Psot field. When Psot=0 (a common "unknown length"
convention), JasPer treats it as invalid and returns -1. The marker segment
is rejected and `jpc_getms` returns NULL, causing the decode loop to emit
`"cannot get marker segment"` and abort.

**Fix:** Set Psot = 12 (SOT header) + 2 (SOD marker) + tile_data_bytes.
For a single empty packet byte: Psot = 15.

### Bug 2: Missing QCD marker

`jpc_dec_cp_isvalid()` (jpc_dec.c lines 1671–1688) checks that both
`JPC_CSET` and `JPC_QSET` flags are set before any tile decoding starts.
Without a QCD (or QCC) marker in the main header, `JPC_QSET` is 0 and the
decoder refuses to proceed.

**Fix:** Include a QCD marker with the correct number of step-size bytes:
- Formula: `numstepsizes = 3 * (numdlvls + 1) - 2` (minimum 1)
- NL=0: Lqcd=4, 1 step-size byte
- NL=5: Lqcd=19, 16 step-size bytes

## Variants Tested

| Variant | Dimensions | NL | Psot | Result |
|---------|------------|----|------|--------|
| v5 | 4×4 | 0 | 15 | Decoded OK — `jp2 1 4 4 8 16` |
| v6 | 32×32 | 5 | 15 | Decoded OK — `jp2 1 32 32 8 1024` |
| v7 | 4096×4096 | 5 | 15 | Decoded OK — `jp2 1 4096 4096 8 16777216` |
| v8 | 256×256 | 5 | 15 | Decoded OK — `jp2 1 256 256 8 65536` |

No ASAN heap-buffer-overflow, SEGV, or UBSAN runtime error was produced by
any variant. LeakSanitizer reports (64-byte `dec->cmpts` leak in error paths)
were excluded from crash detection as they are not memory-safety violations.

## Suggested Fix

Change `mem_seek()` to use a signed type for `newpos`, or add an explicit
upper-bound check before setting `m->pos_`:

```c
// Option A: use signed type so the guard works
ssize_t newpos;
newpos = (ssize_t)offset;      // SEEK_SET
if (newpos < 0 || (size_t)newpos >= m->bufsize_) {
    return -1;
}

// Option B: add an explicit upper-bound check (keep size_t)
size_t newpos;
newpos = (size_t)offset;
if (newpos >= m->bufsize_) {
    return -1;
}
```

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.jp2` (variants v5–v8) |
| `vuln_001_run.sh` | Runs imginfo with ASAN, checks for real crashes |
| `vuln_001_result.txt` | stdout/stderr + ASAN log (generated at runtime) |
| `asan.log.*` | Raw ASAN/UBSAN report files (generated at runtime) |
| `vuln_001_notes.md` | This file |
| `vuln_001_status.txt` | Final verdict (`UNVERIFIED`) |
