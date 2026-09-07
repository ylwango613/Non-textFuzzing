# VULN-001: FoFiType1C::getGlyphName() Heap OOB Read (Latent)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| Function | `FoFiType1C::getGlyphName(int gid)` |
| File | `fofi/FoFiType1C.cc`, lines 166–176 |
| CWE | CWE-125 (Out-of-bounds Read) |
| Severity | Low (latent — zero reachable callers) |
| Status | **SKIPPED** — cannot be triggered by PDF file via pdftotext |

## Vulnerable Code

```cpp
GString *FoFiType1C::getGlyphName(int gid) {
  char buf[256];
  GBool ok;

  ok = gTrue;
  getString(charset[gid], buf, &ok);   // line 171 -- NO BOUNDS CHECK
  if (!ok) {
    return NULL;
  }
  return new GString(buf);
}
```

`charset` is allocated as `gmallocn(nGlyphs, sizeof(Gushort))` — exactly `nGlyphs`
`Gushort` (2-byte) elements. Any `gid` value outside `[0, nGlyphs)` produces a heap
out-of-bounds read at `charset[gid]`.

The nearby `getNameToGIDMap()` (lines 178–193) performs the same `charset[gid]` access
**but** iterates with `for (gid = 0; gid < nGlyphs; ++gid)` — the bounds check is
present there. `getGlyphName()` simply has no equivalent guard.

## Call Graph Analysis

### Path that IS executed during `pdftotext`

```
pdftotext (main)
  -> PDFDoc
     -> Catalog
     -> SplashOutputDev::doUpdateFont()          [SplashOutputDev.cc:1204]
        -> Gfx8BitFont::getCodeToGIDMap(ffT1C)  [GfxFont.cc:1606]
           -> FoFiType1C::getNameToGIDMap()      [FoFiType1C.cc:178]
              // iterates: for (gid = 0; gid < nGlyphs; ++gid)
              // SAFE — no OOB possible
```

### Path that would trigger the OOB (NEVER executed)

```
[hypothetical external caller]
  -> FoFiType1C::getGlyphName(gid)  where gid >= nGlyphs
     -> getString(charset[gid], ...)  <-- HEAP OOB READ
```

### Caller audit result

```
$ grep -rn "getGlyphName" /data/ylwang/non-textfuzz/target/xpdf/
fofi/FoFiType1C.h:167:  GString *getGlyphName(int gid);   <- declaration only
fofi/FoFiType1C.cc:166: GString *FoFiType1C::getGlyphName(int gid) {  <- definition only
```

`getGlyphName()` is declared and defined but has **zero callers** in the xpdf source tree.

## PoC Strategy and Outcome

The PoC constructs a minimal CFF (Type1C) font with `nGlyphs=1` (CharStrings INDEX
count=1, only `.notdef` glyph exists) and embeds it in a PDF as `/FontFile3` with
`/Subtype /Type1C`. A text page references the font to force the font-loading code path.

### CFF binary layout (40 bytes)

```
Offset  Content
 0      Header:           01 00 04 01  (major=1, minor=0, hdrSize=4, offSize=1)
 4      Name INDEX:       count=1, "TestFont"
17      Top DICT INDEX:   count=1, data=[charset@33, charstrings@34, private(0,40)]
29      String INDEX:     count=0 (empty)
31      Global Subr IDX:  count=0 (empty)
33      charset:          00  (format 0, nGlyphs=1 -> 0 SIDs follow)
34      CharStrings IDX:  count=1, data=[0x0e endchar]
40      Private DICT:     (empty, size=0)
```

### What pdftotext actually does with this font

1. `GfxFont.cc:318` detects `FontDescriptor.FontFile3.Subtype = /Type1C` →
   font type set to `fontType1C`
2. `SplashOutputDev.cc:1374` calls `FoFiType1C::make(fontBuf, len)` to parse the CFF
3. `GfxFont.cc:1616` calls `ff->getNameToGIDMap()` which safely iterates
   `gid=0..0` (nGlyphs=1), adds `{".notdef" -> 0}` to the hash map
4. `GfxFont.cc:1617-1626` looks up glyph names from the PDF's encoding in the map
5. **`getGlyphName()` is never invoked**

### Pre-existing unrelated UBSan hit

Running pdftotext produces a UBSan error in `XRef.cc:1258` about an invalid
`CryptAlgorithm` enum value. This is a pre-existing bug unrelated to the target
vulnerability and also appears on valid PDFs. It is filtered out by the run script.

## Why This Cannot Be Triggered Externally

The `getGlyphName()` API exists as a public member function of `FoFiType1C` but the
xpdf processing pipeline never calls it. The PDF font processing code uses only:

- `getNameToGIDMap()` — builds a `name → GID` hash, iterates bounds-safely
- `getCodeToGIDMap()` — uses the above to map 8-bit char codes to GIDs

To make the OOB exploitable via PDF, one of the following would be needed:
1. A code change that adds `getGlyphName()` call(s) to the rendering path, or
2. A code change that passes a PDF-controlled, unchecked value as the `gid` argument

Without such a change, the bug is a **code quality / API contract issue**: the function
is unsafe but unused, posing risk only if future code adds callers without reading the
missing bounds check.

## Recommended Fix

Add a bounds check at the start of `getGlyphName()`:

```cpp
GString *FoFiType1C::getGlyphName(int gid) {
  char buf[256];
  GBool ok;

  if (gid < 0 || gid >= nGlyphs) {   // ADD THIS CHECK
    return NULL;
  }
  ok = gTrue;
  getString(charset[gid], buf, &ok);
  if (!ok) {
    return NULL;
  }
  return new GString(buf);
}
```

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Generates `vuln_001.pdf` with embedded CFF (nGlyphs=1) |
| `vuln_001.pdf` | Crafted PDF with minimal Type1C font |
| `vuln_001.cff` | Raw CFF binary (40 bytes) for inspection |
| `vuln_001_run.sh` | Runs pdftotext, analyses output, writes status |
| `vuln_001_result.txt` | pdftotext stdout/stderr from last run |
| `vuln_001_status.txt` | SKIPPED — latent vulnerability, not triggerable |
| `vuln_001_notes.md` | This file |
