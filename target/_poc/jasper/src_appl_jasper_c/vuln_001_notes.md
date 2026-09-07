# VULN 001 — Heap OOB Read (CDEF/CMAP numchans mismatch)

## Vulnerability

**File:** `src/libjasper/jp2/jp2_dec.c`, lines 402–413  
**Binary:** `imginfo` (ASAN instrumented)

The loop at line 403 iterates `dec->numchans` times, which is set from the CMAP box:

```c
dec->numchans = dec->cmap ? dec->cmap->data.cmap.numchans : ...;
```

Later (line 402–413), if a CDEF box is also present, the same `dec->numchans` bound is used to index into `dec->cdef->data.cdef.ents[]`:

```c
if (dec->cdef) {
    for (i = 0; i < dec->numchans; ++i) {          // numchans = 3 (from CMAP)
        if (dec->cdef->data.cdef.ents[i].channo ...) // ents[] has only 1 entry!
```

`dec->cdef->data.cdef.ents` is allocated with size = CDEF's own `numchans` (1). When CMAP numchans (3) > CDEF numchans (1), the loop reads 2 entries beyond the heap buffer.

## PoC Construction

`vuln_001.jp2` is crafted with:

- **CMAP box**: 3 channels, all palette-mapped (`mtyp=1`) → sets `dec->numchans = 3`
- **PCLR box**: 4-entry, 1-column palette (required when CMAP is present)
- **CDEF box**: only 1 channel entry → `ents[]` allocated for 1 element only
- **Codestream**: minimal 1-component 1×1 JPEG-2000 image

The PCLR box must appear before CMAP in the jp2h superbox. CDEF appears after CMAP.

Box order inside jp2h: `ihdr → bpcc → colr → pclr → cmap → cdef`

## Expected ASAN Output

ASAN should report a `heap-buffer-overflow` READ at `jp2_dec.c:405` (or the surrounding lines), triggered on the second loop iteration (`i=1`) when `dec->cdef->data.cdef.ents[1]` is accessed beyond the 1-element buffer:

```
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size N at ... jp2_dec.c:405
```

## Execution

```bash
chmod +x vuln_001_run.sh
bash vuln_001_run.sh
cat vuln_001_result.txt
```
