# VULN 003 – AP4_Stz2Atom Integer Overflow → Heap Buffer Overflow

## Status
**VERIFIED_CRASH** – AddressSanitizer confirms heap-buffer-overflow on first run.

## Root Cause
In `AP4_Stz2Atom::AP4_Stz2Atom` (Ap4Stz2Atom.cpp), the table size calculation:

```cpp
table_size = (sample_count * m_FieldSize + 7) / 8;
```

is performed using 32-bit arithmetic. When `field_size = 16` and `sample_count = 0x10000000`:

```
0x10000000 * 16 = 0x100000000   →   overflows 32-bit → 0
table_size = (0 + 7) / 8 = 0
```

A 0-byte (actually 1-byte due to ASAN minimum allocation) buffer is then allocated, and
the constructor immediately begins reading `m_FieldSize`-sized entries from the stream into
this buffer, causing an OOB read at index i=1.

## Exploit Details

| Parameter    | Value          | Notes                          |
|--------------|----------------|--------------------------------|
| field_size   | 16 (0x10)      | 2 bytes per sample             |
| sample_count | 0x10000000     | 268,435,456 samples            |
| Overflow     | 32-bit integer | 0x10000000 × 16 = 0x100000000 |
| table_size   | 0              | Integer overflow result        |
| ASAN error   | heap-buffer-overflow READ +1 byte past 1-byte alloc |

## ASAN Output (key lines)
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000151
READ of size 1 at 0x502000000151 thread T0
  #0 in AP4_Stz2Atom::AP4_Stz2Atom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)
  ...
0x502000000151 is located 0 bytes to the right of 1-byte region [0x502000000150,0x502000000151)
allocated by thread T0 here:
  #1 in AP4_Stz2Atom::AP4_Stz2Atom(...)
```

## Trigger Path
```
main
  → AP4_File::AP4_File
    → AP4_File::ParseStream
      → AP4_AtomFactory::CreateAtomFromStream (moov)
        → AP4_MoovAtom::AP4_MoovAtom
          → AP4_ContainerAtom (moov → trak → mdia → minf → stbl)
            → AP4_AtomFactory::CreateAtomFromStream (stz2)
              → AP4_Stz2Atom::Create
                → AP4_Stz2Atom::AP4_Stz2Atom  ← CRASH
```

## PoC File Structure (469 bytes total)
- `ftyp` box (20 bytes): isom brand
- `moov` box containing:
  - `mvhd` (version 0 movie header)
  - `trak` containing:
    - `tkhd` (track header, version 0)
    - `mdia` containing:
      - `mdhd` (media header, version 0)
      - `hdlr` (handler = soun)
      - `minf` containing:
        - `smhd` (sound media header)
        - `dinf` + `dref` (data reference)
        - `stbl` containing:
          - `stsd`, `stts`, `stsc`, `stco` (minimal stubs)
          - **`stz2`** (malicious: field_size=16, sample_count=0x10000000)

## Reproduction
```bash
python3 vuln_003_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=asan.log" \
  mp42aac vuln_003.mp4 /dev/null
```

## Impact
- **Type**: Heap buffer overflow (OOB read; loop would also write on field_size=16 if not caught)
- **CVSS-ish**: Medium–High; reachable from a normal file-open call, no interaction needed
- **Affected component**: `AP4_Stz2Atom` constructor, triggered by any ISO BMFF parser path
  that encounters a malformed `stz2` box (mp42aac, mp4dump, mp4info, etc.)
- **Fix**: Validate `sample_count * field_size` against a 64-bit intermediate before allocation,
  or cap `sample_count` and `field_size` to values that cannot overflow `AP4_UI32`.
