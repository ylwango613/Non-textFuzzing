# VULN 002: AP4_Stz2Atom Integer Overflow → Heap Buffer Over-Read

## Vulnerability Summary

**File:** `Ap4Stz2Atom.cpp`, lines 88–121  
**Binary:** `mp42aac` (ASAN+UBSAN build)  
**Class:** Integer overflow → insufficient buffer allocation → heap-buffer-overflow

## Root Cause

The `AP4_Stz2Atom` constructor computes the buffer size for compressed sample entries using:

```cpp
unsigned int table_size = (sample_count * m_FieldSize + 7) / 8;
```

Both `sample_count` (AP4_UI32) and `m_FieldSize` (AP4_UI08, promoted to `unsigned int`) are 32-bit operands. When:

- `field_size = 4`
- `sample_count = 0x40000001`

The multiplication `0x40000001 * 4 = 0x100000004` overflows 32-bit arithmetic to `4`. So:

```
table_size = (4 + 7) / 8 = 1
```

The subsequent size check:

```cpp
if ((table_size + 8) > size) return;
```

evaluates as `(1 + 8) = 9`, which is less than or equal to the atom's actual data size (~21 bytes), so the **guard passes incorrectly**.

## Consequence

1. `new unsigned char[1]` allocates **only 1 byte** for the `buffer`.
2. `m_Entries.SetItemCount(0x40000001)` attempts to allocate ~16 GB (or causes std::bad_alloc).
3. If allocation succeeds (Linux overcommit), the loop:
   ```cpp
   case 4:  m_Entries[i] = buffer[i/2];
   ```
   at `i = 2` reads `buffer[1]` which is **out of bounds** (only `buffer[0]` was allocated) → **heap-buffer-overflow**.

## Trigger

Craft an `stz2` box with:
- `version = 0`, `flags = 0`
- 3 bytes reserved, `field_size = 4`
- `sample_count = 0x40000001` (big-endian)
- Minimal sample data (1 byte)

Embed this inside a valid MP4 container (`ftyp + moov/trak/mdia/minf/stbl + mdat`).

## Expected ASAN Output

```
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at ...
    #0 ... in AP4_Stz2Atom::AP4_Stz2Atom ...
```

Or alternatively `std::bad_alloc` / process abort if the ~16 GB allocation fails.

## Files

| File | Description |
|------|-------------|
| `vuln_002_gen.py` | Generates `vuln_002.mp4` with the malicious `stz2` box |
| `vuln_002_run.sh` | Runs the generator then invokes `mp42aac` under ASAN |
| `vuln_002_notes.md` | This document |
| `vuln_002_status.txt` | Crash verification result |
| `vuln_002.mp4` | The crafted MP4 file |
