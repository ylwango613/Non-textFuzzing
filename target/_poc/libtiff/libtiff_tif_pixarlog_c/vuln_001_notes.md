# VULN 001 - PixarLogDecode heap buffer overflow for 8BITABGR - SKIPPED

## Why This Vulnerability Cannot Be Triggered via tiffsplit

This vulnerability requires `sp->user_datafmt == PIXARLOGDATAFMT_8BITABGR` inside
`PixarLogDecode()`. Two independent reasons prevent tiffsplit from reaching this state:

### Reason 1: tiffsplit uses raw strip access (never invokes the decoder)

`tiffsplit`'s `cpStrips()` function (tools/tiffsplit.c, lines 244-255) reads strips using
`TIFFReadRawStrip()` and writes them using `TIFFWriteRawStrip()`. Raw strip access operates
on compressed bytes directly and never invokes the PixarLog decompressor. `PixarLogDecode()`
is therefore never called when tiffsplit processes a file.

### Reason 2: TIFFTAG_PIXARLOGDATAFMT is a pseudo-tag (not stored in TIFF files)

The source file libtiff/tif_pixarlog.c, line 60, explicitly states:
> "pseudo tag TIFFTAG_PIXARLOGDATAFMT to one of these possible values"

Pseudo-tags are runtime application settings. They cannot be embedded in a TIFF file and
cannot be set by crafting the IFD entries. An attacker supplying only a malicious TIFF file
has no mechanism to influence this value.

### Reason 3: The auto-guess function never selects PIXARLOGDATAFMT_8BITABGR

`PixarLogGuessDataFmt()` (tif_pixarlog.c lines 598-631) is called when `user_datafmt` is
UNKNOWN. It maps BitsPerSample values to format codes:
- 32-bit float  -> PIXARLOGDATAFMT_FLOAT
- 16-bit uint   -> PIXARLOGDATAFMT_16BIT
- 12-bit int    -> PIXARLOGDATAFMT_12BITPICIO
- 11-bit uint   -> PIXARLOGDATAFMT_11BITLOG
- 8-bit uint    -> PIXARLOGDATAFMT_8BIT

`PIXARLOGDATAFMT_8BITABGR` is never returned. No BitsPerSample value embedded in the TIFF
file can cause the decoder to enter the vulnerable `PIXARLOGDATAFMT_8BITABGR` branch.

### Reason 4: tiffsplit never calls TIFFSetField with TIFFTAG_PIXARLOGDATAFMT

A review of all `TIFFSetField` calls in tiffsplit.c confirms that none set
`TIFFTAG_PIXARLOGDATAFMT`. The `CopyField` macro loop copies standard TIFF directory tags
but `TIFFTAG_PIXARLOGDATAFMT` is not included.

## Conclusion

Trigger condition (2) from the vulnerability report - "Application calls
`TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, PIXARLOGDATAFMT_8BITABGR)`" - requires
source-level modification of tiffsplit or a custom application. It cannot be satisfied by
supplying a crafted TIFF file on the command line. The vulnerability is therefore SKIPPED
under the stated rules.
