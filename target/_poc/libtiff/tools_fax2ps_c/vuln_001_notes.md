# VULN-001 PoC Notes: pcompar() OOB Read in fax2ps

## Vulnerability Summary

- **File**: `libtiff/tools/fax2ps.c`
- **Function**: `pcompar()` (lines 309-315), called via `qsort` at line 363
- **CWE**: CWE-125 (Out-of-bounds Read)
- **Severity**: Low (CVSS 3.3)

## Root Cause

`pcompar()` is the comparator passed to `qsort()` for sorting the `pages[]` array:

```c
static int
pcompar(const void* va, const void* vb)
{
    const int* pa = (const int*) va;   // casts void* to int* (4-byte read)
    const int* pb = (const int*) vb;
    return (*pa - *pb);
}
```

The `pages` array is allocated as `uint16*` (2 bytes per element):

```c
uint16 *pages = NULL, npages = 0;
...
pages = (uint16*) malloc(sizeof(uint16));         // 2 bytes per element
pages = (uint16*) realloc(pages, (npages+1)*sizeof(uint16));
...
qsort(pages, npages, sizeof(uint16), pcompar);    // stride = 2 bytes
```

When `qsort` compares the last element `pages[npages-1]`, it passes
`&pages[npages-1]` to `pcompar`. Inside `pcompar`, `*(const int*)pa` reads
4 bytes from a 2-byte element — the high 2 bytes spill past the heap allocation
boundary, constituting a heap-buffer-overflow (OOB read).

## Trigger Path

```
main()
  -> getopt('-p') -> malloc/realloc pages[] (uint16*, 2 bytes per element)
  -> qsort(pages, npages, sizeof(uint16), pcompar)   [line 363]
     -> pcompar() reads *(int*)&pages[i] (4 bytes from 2-byte slot) [OOB]
```

## PoC Approach

1. `vuln_001_gen.py` constructs a minimal valid little-endian TIFF file
   with uncompressed bilevel image data. fax2ps only needs to parse the
   TIFF header and IFD; the OOB read fires *before* any image decoding.

2. `vuln_001_run.sh` invokes:
   ```
   fax2ps -p 1 vuln_001.tif
   ```
   The `-p 1` flag sets `npages=1`, ensuring `qsort` is called, which
   triggers the OOB read in `pcompar`.

## Expected Behavior

- **With ASAN**: `heap-buffer-overflow` or `heap-use-after-free` error at
  the `*pa` dereference in `pcompar()`.
- **Without ASAN**: Silent 2-byte OOB read from heap allocator metadata;
  may or may not produce observable output corruption.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.tif` — minimal valid TIFF |
| `vuln_001_run.sh` | Runs fax2ps and collects ASAN output |
| `vuln_001.tif` | Generated TIFF input file |
| `vuln_001_result.txt` | Captured stdout/stderr + ASAN logs |
| `vuln_001_status.txt` | Final verdict (VERIFIED_CRASH / UNVERIFIED / ERROR) |
