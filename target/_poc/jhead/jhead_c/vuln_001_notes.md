# VULN 001: GPS IFD Unchecked Component-Count Loop OOB Read in WebP EXIF

## Vulnerability Summary

- **Type**: CWE-125 Out-of-bounds Read (Heap Buffer Overflow read)
- **Function**: `ProcessGpsInfo()` in `gpsinfo.c` lines 141-155
- **Binary**: jhead (ASAN+UBSAN build at `/data/ylwang/non-textfuzz/target/jhead/build_test/jhead`)

## Root Cause

The bounds check in `ProcessGpsInfo()` validates only that `Components * BytesPerFormat[Format]` bytes
fit from `OffsetVal` to `ExifLength`:

```c
ByteCount = Components * ComponentSize;  // = 1 * 8 = 8
if (OffsetVal + ByteCount > ExifLength || OffsetVal > 65536)  // PASSES if OffsetVal = ExifLength-8
    ...
ValuePtr = OffsetBase + OffsetVal;
```

However, for `TAG_GPS_LAT` (0x0002) and `TAG_GPS_LONG` (0x0004), the loop always iterates 3 times
regardless of the actual `Components` count:

```c
for (a = 0; a < 3; a++) {           // hardcoded 3 iterations
    den = Get32s(ValuePtr + 4 + a * ComponentSize);   // reads at +4, +12, +20
    Values[a] = ConvertAnyFormat(ValuePtr + a * ComponentSize, Format);  // reads at +0, +8, +16
}
```

With `Components=1` and `OffsetVal=ExifLength-8`:
- `a=0`: reads `OffsetBase+OffsetVal+0..7` → within bounds ✓
- `a=1`: reads `OffsetBase+OffsetVal+8..15` = `ExifLength..ExifLength+7` → **OOB** ✗
- `a=2`: reads `OffsetBase+OffsetVal+16..23` = `ExifLength+8..ExifLength+15` → **OOB** ✗

## Call Chain

```
jhead main()
  → ProcessFile()
    → ReadImgFile()
      → ReadWebpSections()  [reads EXIF chunk, calls process_EXIF(Data, ChunkLen)]
        → process_EXIF()
          → ProcessExifDir()  [IFD0 → TAG_GPSINFO (0x8825)]
            → ProcessGpsInfo()  [GPS IFD → TAG_GPS_LAT (0x0002)]
              → for(a=0;a<3;a++) loop  ← OOB READ HERE
```

## Crafted File Layout

| Offset | Size | Content                                   |
|--------|------|-------------------------------------------|
| 0      | 12   | RIFF header ('RIFF' + size + 'WEBP')     |
| 12     | 18   | VP8X chunk (flags=0x08, 1x1 canvas)      |
| 30     | 60   | EXIF chunk ('EXIF' + 52 + EXIF data)     |

**EXIF data (52 bytes, raw TIFF, little-endian):**

| Offset | Content                                              |
|--------|------------------------------------------------------|
| 0      | TIFF header 'II' + magic 0x002A + IFD0 offset 8    |
| 8      | IFD0: 1 entry → TAG_GPSINFO (0x8825) → offset 26   |
| 26     | GPS IFD: 1 entry → TAG_GPS_LAT (0x0002)             |
|        | Format=5 (URATIONAL), Components=**1**, Offset=**44** |
| 44     | 8 bytes of rational data (numerator=45, denom=1)    |

Key: `OffsetVal=44`, `ExifLength=52`, `44+8=52` → bounds check passes.
But the loop reads up to offset `44+16+7=67` → 15 bytes past end of 52-byte buffer.

## Reproduction

```bash
python3 vuln_001_gen.py    # creates vuln_001.webp
bash vuln_001_run.sh       # runs jhead and checks for ASAN errors
```

## Expected ASAN Output

```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 4 at 0x... thread T0
    #0 ... in Get32s gpsinfo.c
    #1 ... in ProcessGpsInfo gpsinfo.c:144
    ...
```
