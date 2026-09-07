# VULN 001 - Jasper jp2_decode Heap-Buffer-Overflow via PCLR NE=0

## Vulnerability Details

- **File**: `src/libjasper/jp2/jp2_dec.c`
- **Function**: `jp2_decode`
- **Line**: 370
- **Type**: Unchecked `jas_alloc2` return value (null-pointer-dereference / heap-buffer-overflow)

## Root Cause

At line 370 of `jp2_dec.c`:

```c
lutents = jas_alloc2(pclrd->numlutents, sizeof(int_fast32_t));
for (i = 0; i < pclrd->numlutents; ++i) {
    lutents[i] = pclrd->lutdata[cmapent->pcol + i * pclrd->numchans];
}
```

The return value of `jas_alloc2` is never checked for `NULL`. On allocation failure, the subsequent array access dereferences a null pointer.

## Trigger Mechanism (NE=0 Variant)

Setting PCLR's `NE=0` (numlutents=0) causes `jas_alloc2(0, sizeof(int_fast32_t))` to call `malloc(0)`. The ASAN allocator returns a valid minimum-size allocation. The filling loop executes 0 iterations (safe). However, `jas_image_depalettize` is then called with `numlutents=0` and the zero-size `lutents` pointer.

Inside `jas_image.c:jas_image_depalettize`:

```c
for (j = 0; j < cmpt->height_; ++j) {
    for (i = 0; i < cmpt->width_; ++i) {
        v = jas_image_readcmptsample(image, cmptno, i, j);  // returns 128
        if (v < 0) {
            v = 0;
        } else if (v >= numlutents) {   // 128 >= 0 => TRUE
            v = numlutents - 1;          // v = 0 - 1 = -1
        }
        jas_image_writecmptsample(image, newcmptno, i, j,
          lutents[v]);                   // lutents[-1] => HEAP-BUFFER-OVERFLOW
    }
}
```

The pixel value (128) is always >= numlutents (0), so v is clamped to -1, and `lutents[-1]` reads 8 bytes before the start of the allocation. ASAN detects this as a **heap-buffer-overflow on READ**.

## Crafted JP2 Layout

| Box    | Type     | Key fields                          |
|--------|----------|-------------------------------------|
| JP     | jP       | magic = 0x0D0A870A                  |
| ftyp   | ftyp     | brand = jp2                         |
| jp2h   | jp2h     | superbox containing ihdr + colr     |
| ihdr   | ihdr     | 1x1, 1 component, 8-bit             |
| colr   | colr     | EnumCS=17 (grayscale)               |
| **pclr** | pclr  | **NE=0**, NPC=1, Bi[0]=0x07        |
| **cmap** | cmap  | CMP=0, **MTYP=1 (palette)**, PCOL=0 |
| jp2c   | jp2c     | valid 1x1 JPC codestream            |

## Sanity Checks Bypassed

- `cmaptno (0) >= jas_image_numcmpts(1)` → false → passes
- `pcol (0) >= pclr.numchans (1)` → false → passes

## Exploit Path

```
imginfo -f evil.jp2
  → jas_image_decode
    → jp2_decode
      → jpc_decode (reads valid 1x1 codestream, succeeds)
      → JP2_CMAP_PALETTE branch (line 369)
        → jas_alloc2(0, 8) = malloc(0) ← unchecked (line 370)
        → jas_image_depalettize(..., numlutents=0, lutents=ptr)
          → lutents[-1] ← HEAP-BUFFER-OVERFLOW (ASAN abort)
```

## ASAN Report Expected

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 8 at 0x... thread T0
    #0 ... in jas_image_depalettize jas_image.c:997
    #1 ... in jp2_decode jp2_dec.c:375
    ...
```

## Files

| File                  | Purpose                                      |
|-----------------------|----------------------------------------------|
| `vuln_001_gen.py`     | Generates `evil.jp2` (Python, struct/bytes)  |
| `vuln_001_run.sh`     | Runs imginfo, captures ASAN output, sets result |
| `vuln_001_notes.md`   | This file                                    |
| `vuln_001_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR          |
| `evil.jp2`            | The crafted malicious JP2 file               |
| `vuln_001_result.log` | Full run log including ASAN report           |
