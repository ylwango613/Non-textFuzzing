# vuln_001 – Stack Buffer Over-Index in bmp_putdata() (bmp_enc.c, lines 284-342)

## Vulnerability Summary

- **File:** `src/libjasper/bmp/bmp_enc.c`
- **Function:** `bmp_putdata()`
- **Lines:** 284–342
- **CWE:** CWE-125 (Out-of-bounds Read) / CWE-787 (Out-of-bounds Write)
- **Type:** Stack Buffer Over-Index via Component Index

## Why This PoC Is SKIPPED

The audit report explicitly states:

> "imginfo does not invoke bmp_encode, so the trigger path is the jasper conversion tool."

The SKIPPED condition for this PoC task requires that the vulnerability be triggerable by passing a crafted image file to the `imginfo` binary on the command line. Because `imginfo` never calls into the BMP encoder path (`bmp_encode` -> `bmp_putdata`), it is impossible to reach the vulnerable code through `imginfo`.

The correct trigger path for this vulnerability is:

```
jasper -f crafted.jp2 -T bmp -o out.bmp
```

This invokes the `jasper` conversion tool, not `imginfo`. Since the task constraint requires `imginfo` as the entry point, and `imginfo` cannot reach `bmp_putdata()`, this PoC is marked **SKIPPED**.

## Attack Vector (for reference)

If the `jasper` binary were the permitted entry point, a PoC would:
1. Craft a JP2 (or other supported input format) image with an abnormal number of image components (e.g., more than 3 or 4 components).
2. Pass it to `jasper` with BMP as the output format: `jasper -f crafted.jp2 -T bmp -o out.bmp`.
3. `bmp_putdata()` iterates over component indices without adequate bounds checking, leading to an out-of-bounds read or write on the stack.

## Conclusion

PoC is **SKIPPED** because the vulnerable code path is unreachable via `imginfo`.
