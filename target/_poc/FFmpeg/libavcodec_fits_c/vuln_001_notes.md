# VULN 001 — Stack OOB Write in FITS Header Parser

## Vulnerability

**File**: `libavcodec/fits.c`, function `avpriv_fits_header_parse_line()`
**Lines**: 163–191 (STATE_NAXIS_N branch)
**CWE**: CWE-787 Out-of-bounds Write

`FITSHeader.naxisn` is declared as `int naxisn[999]` (fits.h line 50), providing
valid indices 0..998. In the `STATE_NAXIS_N` loop the only termination condition is:

```c
header->naxis_index++;
if (header->naxis_index == header->naxis) {
    header->state = STATE_REST;
}
```

There is **no** upper-bound check that `header->naxis_index < 999` before the write:

```c
// line 181 — write happens before any bounds check on naxis_index
if (sscanf(value, "%d", &header->naxisn[header->naxis_index]) != 1) {
```

## Trigger Path Analysis

The trigger path is:
```
ffmpeg -i crafted.fits -f null -
  -> avformat_open_input()
  -> fitsdec.c: fits_read_packet()
  -> fitsdec.c: is_image()
  -> fits.c: avpriv_fits_header_parse_line()  [STATE_NAXIS_N]
```

## PoC Approach

`vuln_001_gen.py` produces a FITS file with:
- `SIMPLE = T` — right-justified at column 30 (required for probe: `memcmp(b, "SIMPLE  =                    T", 30)`)
- `BITPIX = 8` — valid bit-depth
- `NAXIS = -1` — negative value; no non-negativity validation exists, so it is accepted. The stop condition `naxis_index == naxis` compares `unsigned naxis_index` to `int naxis`. With naxis=-1, the comparison is `999 == UINT(-1) = 4294967295` which is never true, keeping the parser in STATE_NAXIS_N.
- `NAXIS1` ... `NAXIS999` — drives naxis_index from 0 to 998, writing all 999 elements of naxisn[] without any bounds check (demonstrating the missing guard).

## Key Constraint Discovered

The naxisn[999] OOB write (index 999 = first out-of-bounds) cannot be triggered
via a FITS file due to the FITS format's 8-character keyword limit:

- `NAXIS1000` is 9 characters, exceeding the 8-char keyword field
- The parser reads at most 8 chars: `"NAXIS100"` → `dim_no = 100`
- The sequential check at line 176 fires BEFORE the write:
  ```c
  if (ret != 1 || dim_no != header->naxis_index + 1)  // 100 != 1000 → error
      return AVERROR_INVALIDDATA;
  ```
- The write at line 181 is never reached for index 999

## Actual Observed Behavior

```
[in#0/fits @ ...] expected NAXIS1000 keyword, found END =
[in#0/fits @ ...] Could not find codec parameters for stream 0 (Video: fits, none): unspecified size
```

The parser:
1. Accepts SIMPLE, BITPIX, NAXIS=-1
2. Executes 999 writes to naxisn[0..998] (all valid — no ASAN error)
3. Fails gracefully at NAXIS1000 with `AVERROR_INVALIDDATA` (before any OOB)
4. No memory error is reported by ASAN

## Summary

The vulnerability (missing bounds check on `naxis_index < 999`) is confirmed as
a real code defect. A fix would add:
```c
if (header->naxis_index >= FF_ARRAY_ELEMS(header->naxisn))
    return AVERROR_INVALIDDATA;
```
before line 181.

However, direct exploitation via a FITS file is blocked by the 8-char keyword
constraint. Exploitation would require either: (a) a non-standard FITS parser
variant that accepts longer keywords, or (b) direct C-level call with a crafted
`FITSHeader` (non-file-based attack surface).
