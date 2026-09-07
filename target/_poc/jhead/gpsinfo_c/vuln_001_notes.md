# VULN 001 - GPS LAT/LONG Heap OOB Read via Components < 3

## CWE
CWE-125: Out-of-bounds Read

## Vulnerable Function
`ProcessGpsInfo()` in `gpsinfo.c`, lines 141-155

## Trigger Path
jhead main() -> ReadJpegFile() -> process_EXIF() -> ProcessExifDir() -> ProcessGpsInfo()

## PoC Idea

The vulnerability lies in the unconditional `for (a=0;a<3;a++)` loop that reads
three URATIONAL components (each 8 bytes) when processing TAG_GPS_LAT or
TAG_GPS_LONG, without checking that the IFD entry's `Components` field >= 3.

The boundary guard only verifies `OffsetVal + ByteCount <= ExifLength`, where
`ByteCount = Components * ComponentSize`.  By setting `Components = 1` and
`ByteCount = 8`, this check passes when `OffsetVal = ExifLength - 8`.

The crafted JPEG APP1 contains a TIFF structure with:
- IFD0: one entry pointing to the GPS IFD (offset 26 from TIFF header)
- GPS IFD: four entries:
  - LatRef (0x0001): ASCII "N", inline
  - **Lat  (0x0002): URATIONAL, Components=1, OffsetVal=104 (= ExifLength-8 = 112-8)**
  - LonRef (0x0003): ASCII "E", inline
  - Lon  (0x0004): URATIONAL, Components=3, OffsetVal=80 (normal, within bounds)

The Lat rational data (8 bytes) is placed at offset 104, the very last 8 bytes
of the 112-byte TIFF buffer.  ExifLength = 112.

Boundary check: 104 + 8 = 112 <= 112 -> PASSES (no error, no early return).

Then the loop reads:
- a=0: ValuePtr+0 .. ValuePtr+7   (offsets 104-111: within bounds, OK)
- a=1: ValuePtr+8 .. ValuePtr+15  (offsets 112-119: **OOB - 8 bytes past end**)
- a=2: ValuePtr+16 .. ValuePtr+23 (offsets 120-127: **OOB - 16 bytes past end**)

Each iteration calls both `Get32s(ValuePtr+4+a*8)` and
`ConvertAnyFormat(ValuePtr+a*8, FMT_URATIONAL)` (which reads 8 bytes), so each
OOB iteration performs two OOB reads of 4 and 8 bytes respectively.

## Expected ASAN Output

AddressSanitizer should report a heap-buffer-overflow (read) in
`ProcessGpsInfo`, with shadow bytes showing the over-read relative to the
EXIF buffer allocated in the JPEG parser.
