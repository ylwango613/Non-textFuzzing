# VULN-001 PoC Notes — Heap OOB Read in ProcessGpsInfo

## Vulnerability Summary

**File**: `gpsinfo.c`, lines 141-154  
**Function**: `ProcessGpsInfo()`  
**Trigger**: GPS IFD tag 0x0002 (TAG_GPS_LAT) with `Format=5` (FMT_URATIONAL)
and `Components=1` (or 2).

The loop
```c
for (a=0;a<3;a++){
    den = Get32s(ValuePtr + 4 + a*ComponentSize);   // line 144
    ...
    Values[a] = ConvertAnyFormat(ValuePtr + a*ComponentSize, Format);  // line 154
}
```
always iterates **3 times**.  The preceding bounds check only validates
`ByteCount = Components * ComponentSize` bytes from `ValuePtr`.  With
`Components=1` and `ComponentSize=8` (FMT_URATIONAL), `ByteCount=8` but
the loop reads up to `ValuePtr+23`.  Iterations `a=1` and `a=2` access
`ValuePtr+8..+15` and `ValuePtr+16..+23` respectively — both are beyond the
validated region.

## PoC Approach

The crafted JPEG contains:

1. **SOI** + **APP1** marker with a malformed EXIF payload.
2. **TIFF header** in Intel (little-endian) byte order, `IFD0` offset = 8.
3. **IFD0**: single entry — GPS sub-IFD pointer (`tag=0x8825`) pointing to
   offset 26.
4. **GPS IFD** at offset 26: three entries in tag order:
   - `0x0000` GPS Version (4-byte inline BYTE)
   - `0x0001` GPS LatRef  (inline ASCII 'N')
   - `0x0002` GPS Lat     (`Format=5`, **`Components=1`**, offset=68)
5. **Rational data** at offset 68: exactly **8 bytes** (one rational: 30/1).

`ExifLength` = 76.  Bounds check: `68+8=76 ≤ 76` → passes.  The loop then
reads `ValuePtr+8` through `ValuePtr+23`, which is `ExifSection[76..91]` —
16 bytes past `ExifLength`.

## Expected Behaviour / ASAN Limitation

`jpgfile.c:130`:
```c
Data = (uchar *)malloc(itemlen + 20);
```
jhead intentionally allocates **20 extra bytes** beyond the nominal section
length to avoid false positives with memory sanitisers when structures
straddle the end of a section.  The maximum OOB extent here is **15 bytes**
past `ExifLength` (bytes at `ExifSection + ExifLength + 0..15`), which falls
entirely within those 20 extra bytes.

Consequence: **ASAN does not fire** (no red-zone boundary is crossed).
The OOB reads access uninitialised heap bytes from the extra allocation,
producing garbage GPS coordinate values, but no crash.

The vulnerability is still real:
- In a custom allocator without padding, or with ASan's `max_redzone` tuned
  down, the OOB would be caught.
- The reads expose up to 16 bytes of uninitialised heap data (information
  leak concern in processing pipelines that mirror EXIF output).
- A coordinated heap layout (e.g. an adjacent freed chunk) could allow the
  attacker to influence the coordinate values printed by jhead.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001_input.jpg` using only Python `struct` |
| `vuln_001_run.sh` | Runs jhead under ASAN and collects output |
| `vuln_001_input.jpg` | Generated malicious JPEG |
| `vuln_001_result.txt` | stdout/stderr + any ASAN error lines |
| `vuln_001_status.txt` | One-line verdict |
