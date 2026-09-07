# PoC Notes: vuln_001 — Signed Integer Overflow in numprcs (JasPer jpc_t2cod.c)

## Vulnerability

**CWE-787**: Out-of-bounds Write  
**Functions**: `jpc_pi_nextrpcl()`, `jpc_pi_nextpcrl()`, `jpc_pi_nextcprl()`  
**Overflow site**: `jpc_dec.c:777` — `rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs;`  
**OOB write site**: `jpc_t2cod.c:308/411/505` — `++(*prclyrno);` with stale `numhprcs`

## Trigger Mechanism

The COD marker sets `Scod=0x01` (custom precinct sizes) with `prcwidthexpn=prcheightexpn=0`
(packed byte `0x00`) for the single resolution level (numdlvls=0). Tile dimensions are
`5 x 858993460` and progression order is RPCL (value=2).

At tile initialisation (`jpc_dec_tileinit`):

```
numhprcs = ceil(tile_width / 2^prcwidthexpn) = ceil(5 / 1) = 5
numvprcs = ceil(tile_height / 2^prcheightexpn) = ceil(858993460 / 1) = 858993460
numprcs  = 5 * 858993460 = 4294967300   <-- signed int32 overflow -> 4
```

`prclyrnos` is then allocated with only 4 slots. The RPCL iterator computes
`prcno = prcvind * numhprcs + prchind = prcvind * 5 + prchind`, which reaches >=4
immediately, writing out of bounds at `prclyrnos[prcno]`.

## Actual Sanitizer Output (Confirmed)

```
jpc_dec.c:777:35: runtime error: signed integer overflow: 46342 * 46341 cannot be represented in type 'int'
    #0 in jpc_dec_tileinit
    #1 in jpc_dec_process_sod
    #2 in jpc_decode
    #3 in jp2_decode
    #4 in jas_image_decode
    #5 in main
```

UBSAN fires immediately when JasPer computes `rlvl->numhprcs * rlvl->numvprcs` at line 777.
JasPer then returns an error ("cannot decode code stream") and exits with code 1.

The `--max-samples 0` flag is required to bypass JasPer's 64M sample guard; without it
the decoder rejects the image before reaching the overflow site.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.jp2` |
| `vuln_001.jp2` | Crafted JPEG-2000 file |
| `vuln_001_run.sh` | Runs imginfo and captures ASAN/UBSAN output |
| `vuln_001_notes.md` | This file |
| `vuln_001_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED |

## Note on Sample Limit

JasPer's default max-samples guard (64 M = `JAS_DEC_DEFAULT_MAX_SAMPLES`) blocks large
images before reaching the overflow. Pass `--max-samples 0` to imginfo to disable it.
The underlying trigger dimensions (46342 x 46341 = 2,147,534,622 > INT_MAX) are chosen
as the minimum needed to cross the int32 overflow boundary. The component buffer
(`~17 GB`) is allocated by `jas_matrix_create` via `mmap`, and the UBSAN fires at line
777 during tile resolution-level initialisation — before any tile pixel decoding.
