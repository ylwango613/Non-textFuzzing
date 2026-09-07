# VULN-001 PoC Notes: Signed Integer Overflow in numprcs

## Vulnerability Summary

**Location:** `jpc_dec_tileinit()` in `jpc_dec.c:777`

**Root Cause:** Signed integer overflow in the expression:
```c
rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs;
```
Both operands are `int`. When `numhprcs = numvprcs = 65537`, the product
`65537 * 65537 = 4,295,098,369 > INT_MAX (2,147,483,647)`, causing UB and
truncation to `131073` (the low 32 bits reinterpreted as signed).

## Trigger Chain

```
imginfo -f evil.jp2
  -> jas_image_decode()
  -> jpc_decode()
  -> jpc_dec_process_siz()   # parses SIZ: 65537x65537 single tile
  -> jpc_dec_process_cod()   # parses COD: RPCL + explicit precinct 0x00
  -> jpc_dec_tileinit()      # OVERFLOW HERE: numprcs = 65537*65537 truncated
     # Under-allocates: jas_alloc2(131073, sizeof(jpc_dec_prc_t))
     #                  jas_alloc2(131073, sizeof(long)) for prclyrnos
  -> jpc_dec_decodepkts()
  -> jpc_pi_next()
  -> jpc_pi_nextrpcl()       # OOB: prcno = prcvind*65537 + prchind >= 131073
     # pirlvl->prclyrnos[prcno] -> OOB write (heap)
     # band->prcs[prcno]        -> OOB read  (heap)
```

## JP2 Construction Strategy

### Key Parameters

1. **SIZ Marker**
   - `Xsiz = Ysiz = 65537` (image dimensions)
   - `XTsiz = YTsiz = 65537` (single tile covers whole image)
   - `Csiz = 1` (single grayscale component)

2. **COD Marker**
   - `Scod = 0x01`: explicit precinct sizes enabled
   - `ProgOrder = 0x02`: RPCL (Resolution-Position-Component-Layer)
   - `numDecompLvls = 1`
   - `precinct_size bytes = 0x00`: `prcwidthexpn = prcheightexpn = 0`
     - `prec_width = 2^0 = 1` pixel per precinct
     - `numhprcs = ceil(65537/1) = 65537`
     - `numvprcs = ceil(65537/1) = 65537`

3. **SOT/SOD**: minimal tile-part header + empty data to let the parser
   reach `jpc_dec_tileinit()`.

### Overflow Math

```
numhprcs = 65537
numvprcs = 65537
product  = 65537 * 65537 = 4,295,098,369

As signed 32-bit: 4,295,098,369 - 2^32 = -131072  (negative!) or
  depending on UB behavior, may wrap to 131073 (= 4295098369 % 2^32 - 2^32 sign)
  Actually: 4295098369 % 2^32 = 131073 (unsigned), as int32 = 131073 (positive)

Allocated: jas_alloc2(131073, sizeof(jpc_dec_prc_t))
True needed: jas_alloc2(65537*65537, ...) = ~4 billion entries -> OOM/truncation

OOB at: prcvind=2, prchind=0 => prcno = 2*65537 + 0 = 131074 >= 131073
```

## Expected Outcomes

- **ASAN heap-buffer-overflow**: on `pirlvl->prclyrnos[131074]` write or
  `band->prcs[131074]` read
- **UBSAN signed-integer-overflow**: at the multiplication site in `jpc_dec.c`
- **OOM / DoS**: if the runtime attempts to allocate based on true dimensions
- **Crash / SIGSEGV**: if ASAN is not instrumented, raw memory corruption

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Python script generating `vuln_001.jp2` |
| `vuln_001.jp2` | Malicious input file |
| `vuln_001_run.sh` | Shell script to run imginfo and collect output |
| `vuln_001_result.txt` | Combined stdout/stderr + ASAN grep |
| `asan.log.*` | Raw ASAN output (if instrumented build) |
| `vuln_001_status.txt` | Final verification status |
