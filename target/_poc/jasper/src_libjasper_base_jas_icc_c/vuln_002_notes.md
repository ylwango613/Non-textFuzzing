# VULN 002 - Heap Buffer Underwrite in jas_icctxt_input (cnt=0)

## Overview

**CWE**: CWE-787 (Out-of-bounds Write)  
**File**: `src/libjasper/base/jas_icc.c`, lines 1214-1218  
**Function**: `jas_icctxt_input()`

## Root Cause

In `jas_iccprof_load()` (line 340):

```c
len = tagtabent->len - 8;
if ((*attrval->ops->input)(attrval, in, len)) { ... }
```

When `tagtabent->len == 8` (the minimum header size for a tag: 4-byte type
signature + 4-byte reserved), `len = 0`. This value is passed as `cnt` to
`jas_icctxt_input()`.

Inside `jas_icctxt_input()` (lines 1214-1218):

```c
if (!(txt->string = jas_malloc(cnt)))       // (1) malloc(0) returns non-NULL
    goto error;
if (jas_stream_read(in, txt->string, cnt) != cnt)  // (2) reads 0 bytes, passes
    goto error;
txt->string[cnt - 1] = '\0';               // (3) txt->string[-1] = '\0' !!!
```

Step (3) with `cnt=0` computes `txt->string[-1]`, writing one byte **before**
the start of the 0-byte heap allocation. Under ASAN, this is detected as a
**heap-buffer-overflow (underwrite)** because `malloc(0)` returns a non-NULL
pointer to a zero-byte region, and any access before that region falls in the
left redzone.

## Trigger Condition

A JP2 file with:
- A COLR box using `method=2` (ICC Restricted Profile)
- An embedded ICC profile containing a TXT-type tag (e.g., 'cprt'/copyright)
  whose **tag table entry `len` field equals exactly 8**

## Call Path

```
imginfo -f crafted.jp2
  -> jas_image_decode()
  -> jp2_decode()
     - reads boxes until jp2c found (stores colr box for later)
     - jpc_decode() decodes the JPEG-2000 codestream
     - processes colr box: method=2 -> jas_iccprof_createfrombuf()
       -> jas_iccprof_load()
          -> jas_iccprof_readhdr()   (reads 128-byte header)
          -> jas_iccprof_gettagtab() (reads tag table: cprt, off=144, len=8)
          -> loop over tags:
             - reads type signature 'text' (JAS_ICC_TYPE_TXT)
             - len = 8 - 8 = 0
             -> jas_icctxt_input(attrval, in, cnt=0)
                -> malloc(0) returns non-NULL ptr
                -> read 0 bytes (ok)
                -> ptr[-1] = '\0'  <== HEAP UNDERWRITE / ASAN ABORT
```

## PoC Structure

### `vuln_002_gen.py`

Constructs a JP2 file by:
1. Building a 152-byte ICC profile:
   - 128-byte header (zeros, no field validation in jas_iccprof_readhdr)
   - Tag count = 1
   - Tag table entry: sig='cprt', offset=144, **len=8** (the trigger)
   - Tag data at offset 144: type='text', reserved=0 (8 bytes total)
2. Embedding it in a COLR box with `method=2`
3. Using the valid JPEG-2000 codestream from the existing test file
   `jasper/data/test/good/109-PoC.jp2` (32x32, 2-component image) as the
   jp2c content so that `jpc_decode()` succeeds and control reaches the ICC
   parsing code.

### `vuln_002.jp2`

The crafted input file triggering the bug.

## Expected ASAN Output

```
=================================================================
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size 1 at 0x... thread T0
    #0 0x... in jas_icctxt_input .../jas_icc.c:1218
    #1 0x... in jas_iccprof_load .../jas_icc.c:341
    ...
```

The access is a write of 1 byte to the address immediately before the
0-byte malloc region (left redzone).
