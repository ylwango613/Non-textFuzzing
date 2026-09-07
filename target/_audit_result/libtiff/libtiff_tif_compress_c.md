**Analysis summary:**

The file is 295 lines. I read it completely and traced all key patterns:

**`TIFFGetConfiguredCODECs()` (lines 252–260)**  
`_TIFFmemcpy(codecs + i - 1, cd, sizeof(TIFFCodec))` copies from `cd` (a `codec_t*`) instead of `cd->info` (the actual `TIFFCodec*`). This is a logic/correctness bug but **not** an OOB read: the allocation in `TIFFRegisterCODEC` is `sizeof(codec_t) + sizeof(TIFFCodec) + strlen(name)+1` = 16 + 24 + n bytes, so reading `sizeof(TIFFCodec) = 24` bytes from the start of `cd` stays within the allocated block. Additionally, `TIFFGetConfiguredCODECs()` is not called from any TIFF file parsing path — it only appears in `tiffio.h` as a public API export with no callers in parsing or tool code.

**`TIFFRegisterCODEC()` (line 197)**  
`_TIFFmalloc(sizeof(codec_t) + sizeof(TIFFCodec) + strlen(name)+1)` — `name` is a parameter from application code registering a codec, not from TIFF file content; not externally triggerable.

**`TIFFSetCompressionScheme()` (lines 153–165)**  
Called with the compression tag value from the TIFF file (`tif_dir.c:196`), but only performs a codec lookup and calls the codec's `init` function — no malloc or buffer copy with file-controlled sizes.

**`TIFFFindCODEC()`** — pure linear search through static and registered lists, no allocation.

**All `_TIFFNo*` stubs** — no memory operations.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
