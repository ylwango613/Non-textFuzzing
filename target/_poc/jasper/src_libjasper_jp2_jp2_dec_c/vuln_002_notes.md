# VULN 002 — Heap Buffer Over-read in jp2_decode() BPCC bpcs Array

## Classification
- **CWE**: CWE-125 — Out-of-bounds Read
- **Location**: `src/libjasper/jp2/jp2_dec.c`, lines 274–281
- **Function**: `jp2_decode()`

## Root Cause

In `jp2_bpcc_getdata()` (`jp2_cod.c:381`):
```c
bpcc->numcmpts = box->datalen;   // attacker-controlled
bpcc->bpcs = jas_alloc2(bpcc->numcmpts, sizeof(uint_fast8_t));
```
The `bpcs` array is allocated with `numcmpts = box->datalen` (i.e., the raw byte length of the BPCC box payload).

In `jp2_decode()` (`jp2_dec.c:274–281`), when components have different bit depths (`samedtype == false`):
```c
for (i = 0; i < jas_image_numcmpts(dec->image); ++i) {
    if (jas_image_cmptdtype(dec->image, i) !=
        JP2_BPCTODTYPE(dec->bpcc->data.bpcc.bpcs[i])) {  // OOB if i >= bpcc->numcmpts
        jas_eprintf("warning: component data type mismatch\n");
    }
}
```
The loop iterates over the JPC image's component count (from the decoded codestream), but the BPCC `bpcs[]` array was sized from the BPCC box's `datalen`. When `datalen < numcmpts_in_jpc`, this is a heap buffer over-read.

Critically, the warning at lines 268–270 does **not** terminate processing:
```c
if (dec->bpcc->data.bpcc.numcmpts != jas_image_numcmpts(dec->image)) {
    jas_eprintf("warning: number of components mismatch\n");
    // NO goto error here!
}
```

## Trigger Conditions

1. JP2 BPCC box with `datalen=1` → `bpcs[0]` only (1-element array)
2. JP2 ihdr with `bpc=0xFF` (signals BPCC box present, variable bit depths)
3. JPC codestream with `Csiz=3` and mixed Ssiz values:
   - Component 0: `Ssiz=0x07` (8-bit unsigned)
   - Component 1: `Ssiz=0x09` (10-bit unsigned) ← different
   - Component 2: `Ssiz=0x07` (8-bit unsigned)
   → `samedtype=false` → enters the vulnerable loop
4. Loop reads `bpcs[0]`, `bpcs[1]` (OOB), `bpcs[2]` (OOB)

## PoC Structure

- **`vuln_002_gen.py`**: Generates `vuln_002.jp2` with the conditions above
- **`vuln_002.jp2`**: The malformed JP2 file
- **`vuln_002_run.sh`**: Runs `imginfo` with ASAN and captures output
- **`vuln_002_result.txt`**: Execution output including any ASAN reports

## JP2 File Layout

```
Signature box (12 bytes)          — fixed magic
File Type box (ftyp, 20 bytes)    — brand jp2
JP2 Header superbox (jp2h)
  ihdr box (22 bytes)             — ncomp=3, bpc=0xFF
  colr box (15 bytes)             — sRGB enumerated
  BPCC box (9 bytes)              — payload=1 byte ONLY (triggers OOB)
Codestream box (jp2c)
  JPC codestream:
    SOC FF4F
    SIZ (3 comps, Ssiz=[0x07,0x09,0x07], 1x1 image)
    COD (0 decomp levels, reversible transform)
    QCD (no quantization)
    SOT (tile 0)
    SOD + minimal tile data
    EOC FF D9
```

## Expected ASAN Output

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1 at 0x...
  in jp2_decode src/libjasper/jp2/jp2_dec.c:278
```
