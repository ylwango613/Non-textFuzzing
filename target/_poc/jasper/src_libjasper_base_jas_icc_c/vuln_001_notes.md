# VULN 001 — Heap OOB Write in `jas_icctxtdesc_input` (asclen == 0)

## Vulnerability Summary

- **CWE**: CWE-787 (Out-of-bounds Write)
- **File**: `jasper/src/libjasper/base/jas_icc.c`
- **Function**: `jas_icctxtdesc_input()`
- **Lines**: 1101–1108

## Root Cause

```c
/* line 1101 */ if (jas_iccgetuint32(in, &txtdesc->asclen))
                    goto error;
/* line 1103 */ if (!(txtdesc->ascdata = jas_malloc(txtdesc->asclen)))
                    goto error;
/* line 1105 */ if (jas_stream_read(in, txtdesc->ascdata, txtdesc->asclen) !=
                  JAS_CAST(int, txtdesc->asclen))
                    goto error;
/* line 1108 */ txtdesc->ascdata[txtdesc->asclen - 1] = '\0';   // BUG
```

When `asclen == 0` (read from attacker-controlled ICC profile data):

1. `jas_malloc(0)` returns a **non-NULL** pointer on Linux/glibc (implementation-defined).
2. `jas_stream_read(in, ascdata, 0)` returns `0` which equals `JAS_CAST(int, 0)`, so the check passes.
3. `txtdesc->asclen` is `uint_fast32_t`. Computing `0 - 1` in unsigned arithmetic wraps to `UINT_FAST32_MAX` (≈ 1.8 × 10¹⁹ on 64-bit platforms).
4. The write `ascdata[UINT_FAST32_MAX] = '\0'` accesses a byte far past the end of the heap allocation → **heap buffer overflow / SIGSEGV**.

## Trigger Condition

The bug fires whenever a JP2 file is parsed that:
- Contains a COLR box with `method=2` (JP2_COLR_ICC_RESTRICTED)
- Embeds an ICC profile with a `desc` tag (type signature `0x64657363`)
- Sets the `asclen` field (bytes 0–3 of the TXTDESC tag payload) to `0x00000000`

## PoC Approach

The crafted file (`vuln_001.jp2`) is a minimal JP2 with:

1. **JP2 signature** and **FTYP** boxes — standard required header.
2. **JP2H** super-box containing:
   - **IHDR**: declares 32×32, 2-component image (matches embedded codestream).
   - **COLR**: `method=2` (ICC), carries the malformed ICC profile.
3. **JP2C**: contains a valid 32×32 JPEG 2000 codestream extracted from
   JasPer's own test data (`jasper/data/test/good/109-PoC.jp2`). A valid
   codestream is required because `jp2_decode()` calls `jpc_decode()` **before**
   processing the COLR box.

### ICC Profile Layout (234 bytes total)

| Offset | Size | Content |
|--------|------|---------|
| 0      | 128  | ICC header (profile size, version, class `mntr`, colorspace `RGB `) |
| 128    | 4    | Tag count = 1 |
| 132    | 12   | Tag table: sig=`desc` (0x64657363), offset=144, size=90 |
| 144    | 4    | Type signature = `desc` |
| 148    | 4    | Reserved = 0 |
| 152    | 4    | **asclen = 0x00000000** ← triggers bug |
| 156    | 78   | Remaining TXTDESC fields (uclangcode, uclen, sccode, maclen, macdata) |

### Call Path

```
imginfo -f vuln_001.jp2
  jp2_decode()
    jp2_box_get()           → reads COLR box, stores ICC bytes
    jpc_decode()            → decodes valid codestream (must succeed)
    jas_iccprof_createfrombuf()
      jas_iccprof_load()
        jas_iccprof_readhdr()      → reads 128-byte ICC header
        jas_iccprof_gettagtab()    → reads 1-entry tag table
        // loop over tags:
        jas_iccgetuint32()         → reads type_sig ('desc')
        jas_stream_gobble(in, 4)   → skips reserved
        jas_icctxtdesc_input()     → cnt = TAG_SIZE - 8 = 82
          jas_iccgetuint32() → asclen = 0
          jas_malloc(0)      → returns non-NULL ptr
          jas_stream_read(in, ascdata, 0) → reads 0 bytes, returns 0 ✓
          ascdata[0 - 1] = '\0'   CRASH (OOB write at UINT_FAST32_MAX offset)
```

## Expected ASAN Output

ASAN (with UBSAN) should report one of:
- `heap-buffer-overflow` on WRITE of size 1
- `SEGV on unknown address` (if the address wraps past any mapped page)

The crash stack trace should point to `jas_icctxtdesc_input` in `jas_icc.c:1108`.

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Generates `vuln_001.jp2` with malformed ICC profile |
| `vuln_001_run.sh` | Runs imginfo and captures ASAN output |
| `vuln_001.jp2` | Crafted input file |
| `vuln_001_result.txt` | Combined stdout/stderr + ASAN log |
| `asan.log.*` | Raw ASAN output |
