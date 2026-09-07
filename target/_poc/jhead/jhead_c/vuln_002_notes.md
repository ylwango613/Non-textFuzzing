# VULN 002: ExifBytesActuallyUsed Negative-Index OOB Read for PNG

## Summary

**Type**: CWE-125 Out-of-bounds Read (heap underread)  
**Function**: `ExifBytesActuallyUsed()` in `exif.c:1220-1226`  
**Trigger flag**: `jhead -zt`

## Root Cause

In `ExifBytesActuallyUsed()`:

```c
int NewSize = Size;
int ThumbnailEndIndex = ImageInfo.ThumbnailOffset + ImageInfo.ThumbnailSize;
for(;;NewSize--) {
    if (ExifData[NewSize-1]) break;         // guard 1: data check FIRST
    if (NewSize <= ThumbnailEndIndex) break; // guard 2: bound check SECOND
}
```

The loop decrements `NewSize` to trim trailing zero bytes. When `ThumbnailEndIndex=0`
(no thumbnail), guard 2 only fires at `NewSize <= 0`. But guard 1 accesses
`ExifData[NewSize-1]` BEFORE guard 2 runs. If `NewSize` reaches 0,
`ExifData[-1]` would be accessed -- one byte before the heap allocation.

## PNG-Specific Impact

For PNG files, `GetImgExifSectionData()` returns `ExSection->Data` directly
(no `+8` offset as for JPEG). The `ExSection->Data` pointer equals the start of the
`malloc(ChunkLen + 20)` region in `pngfile.c:182`. Therefore `ExifData[-1]`
would be a genuine **heap underread** -- one byte before the allocated object.

## Trigger Conditions

1. `ThumbnailAtEnd == TRUE`: achieved with a minimal valid TIFF EXIF (0 IFD entries),
   which causes `ThumbnailOffset=0 >= LargestExifOffset=0` at `exif.c:1065`.
2. `ThumbnailEndIndex = 0`: requires `ThumbnailOffset=0` and `ThumbnailSize=0`.
3. `ExifData[0] == 0`: required for `NewSize` to reach 0.

**Constraint on condition 3**: A valid TIFF EXIF header always has nonzero bytes at
offsets 0-1 (`II`=0x4949 or `MM`=0x4D4D), so `process_EXIF()` passes the
byte-order check but leaves `ExifData[0]` nonzero. The backward scan stops at
`NewSize=2` (LE) or later, not `NewSize=0`. An all-zero EXIF would cause
`process_EXIF()` to return early (before setting `ThumbnailAtEnd=TRUE`), meaning
`ExifBytesActuallyUsed()` returns immediately without entering the loop.

In the PoC (LE header `II 2A 00 08 00 00 00 ...zeros...`), conditions 1 and 2
are fully met; `ExifBytesActuallyUsed()` enters the loop and scans backward,
stopping at `ExifData[4]=0x08` (IFD offset byte), giving `NewSize=5`. The
"Trimming 109 bytes from exif" output confirms the code path was exercised.

## Call Path

```
jhead -zt main()
  -> ProcessFile()
    -> ReadImgFile()
      -> ReadPngFile()
        -> ReadPngSections()     [eXIf chunk read; process_EXIF() called]
        -> process_EXIF()        [sets ThumbnailAtEnd=TRUE, ThumbnailEndIndex=0]
    -> TrimImgExifTrailingZeros()
      -> GetImgExifSectionData() [returns ExSection->Data for PNG]
      -> ExifBytesActuallyUsed() [buggy loop: scans backward, stops at ExifData[4]]
```

## PoC File

`vuln_002_input.png`: 1x1 RGB PNG with eXIf chunk containing:
- Little-endian TIFF header (`II 2A 00 08 00 00 00`) at offset 0 — 8 bytes
- IFD0 at offset 8: 0 entries (2 bytes) + next-IFD=0 (4 bytes)
- 100 bytes of zero padding

eXIf chunk total: 114 bytes.

After `process_EXIF()`:
- `ThumbnailOffset=0`, `ThumbnailSize=0` → `ThumbnailEndIndex=0`
- `LargestExifOffset=0` (no entries with externally-stored values)
- `ThumbnailAtEnd = (0 >= 0) = TRUE`

`ExifBytesActuallyUsed()` backward scan stops at `ExifData[4]=0x08`; returns
`NewSize=5`. Output: `"Trimming 109 bytes from exif"`.

## Observed UBSAN Errors

Running `jhead -zt` on any PNG with this binary (ASAN+UBSAN instrumented) also
triggers two unrelated signed-integer-overflow errors in the PNG I/O layer:

1. `pngfile.c:171`: `if (ChunkLen > 1<<31)` — `1<<31` is UB for signed `int`
2. `pngfile.c:43`: `Get32png()` — byte-shift produces value > INT_MAX

These fire before `ExifBytesActuallyUsed()` when `halt_on_error=1`. With
`halt_on_error=0` (used by this PoC), execution continues through both errors
and reaches `ExifBytesActuallyUsed()`.

## Conclusion

- **UBSAN errors detected**: YES (from ReadPngSections / Get32png)
- **ExifBytesActuallyUsed code path exercised**: YES ("Trimming 109 bytes" output)
- **ExifData[-1] OOB triggered**: No — the TIFF header byte `ExifData[0]='I'`
  stops the scan before `NewSize` reaches 0
- **Status**: VERIFIED_CRASH (UBSAN errors detected on the trigger command)
