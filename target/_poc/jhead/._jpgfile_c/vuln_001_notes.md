# VULN 001: GPS Lat/Long Out-of-Bounds Read via Under-counted Components

## CWE
CWE-125: Out-of-bounds Read

## Vulnerability Location
`gpsinfo.c`, function `ProcessGpsInfo()`, lines 141-155

## Root Cause
For `TAG_GPS_LAT` (0x0002) and `TAG_GPS_LONG` (0x0004) entries with
`Format=FMT_URATIONAL (5)`, the code contains a fixed loop:

```c
for (a=0;a<3;a++){
    den = Get32s(ValuePtr+4+a*ComponentSize);   // ComponentSize=8
    ...
    Values[a] = ConvertAnyFormat(ValuePtr+a*ComponentSize, Format);
}
```

The preceding bounds check (line 110) only validates
`OffsetVal + Components*ComponentSize <= ExifLength`,
where `Components` comes from the EXIF entry. When `Components=1`
(undercounted; normal is 3) the check passes with `ByteCount=8`,
but the loop unconditionally reads at offsets `+0`, `+8`, `+16`
from `ValuePtr` — consuming 24 bytes total — causing 16 bytes of
out-of-bounds memory read.

## Trigger Path
```
jhead main()
  -> ReadImgFile()
    -> ReadJpegFile()
      -> ReadJpegSections() [reads APP1 section into heap buffer]
        -> process_EXIF(Data+8, itemlen-8)
          -> ProcessExifDir() [TAG_GPSINFO handler]
            -> ProcessGpsInfo(SubdirStart, OffsetBase, ExifLength)
               LOOP a=0,1,2 with Components=1 => OOB at a=1, a=2
```

## Crafted File Design
- JPEG with minimal APP1/EXIF segment (76 bytes total)
- TIFF section (little-endian, 64 bytes = ExifLength)
- IFD0 has one entry: TAG_GPSINFO pointer to GPS IFD at offset 26
- GPS IFD has two entries (Lat + Long):
  - Format=5 (URATIONAL, ComponentSize=8)
  - Components=1 (instead of the correct 3)
  - OffsetVal=56 (= ExifLength-8)
- GPS data: 8 bytes placed at the very end of the EXIF buffer

The bounds check:
  `56 + 1*8 = 64 = ExifLength`  ->  NOT > ExifLength  ->  PASSES

The loop then reads:
  a=0: ValuePtr+0  (bytes 56-63)  in-bounds
  a=1: ValuePtr+8  (bytes 64-71)  OOB (+8 past ExifLength)
  a=2: ValuePtr+16 (bytes 72-79)  OOB (+16 past ExifLength)

## Expected Observable Behaviour
With ASAN/UBSAN instrumented binary:
- `AddressSanitizer: heap-buffer-overflow` on READ of size 4 or 8
- The report should point to `gpsinfo.c` in the `ProcessGpsInfo` function

Without sanitizer: silent read of heap memory past the allocated buffer,
potentially leaking or crashing depending on heap layout.
