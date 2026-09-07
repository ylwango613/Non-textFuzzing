# VULN 001: Integer Underflow in `bytes_available` — `AP4_DrefAtom::AP4_DrefAtom()`

## Vulnerability Summary

**File**: `Source/C++/Core/Ap4DrefAtom.cpp`, line 81  
**Type**: Integer underflow / unsigned wraparound → out-of-bounds atom parsing  
**Sanitizer build**: ASAN + UBSAN (`-fsanitize=address,undefined`)

### Root Cause

```cpp
// Ap4DrefAtom.cpp, private constructor (line 69-90)
AP4_DrefAtom::AP4_DrefAtom(AP4_UI32 size, ..., AP4_ByteStream& stream, ...)
    : AP4_ContainerAtom(...)
{
    AP4_UI32 entry_count;
    stream.ReadUI32(entry_count);                          // reads 4 bytes

    // VULNERABLE LINE 81 — unsigned subtraction can underflow:
    AP4_LargeSize bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 4;
    //                              ^^^^ AP4_UI32                ^^^^
    //  When size = 12:  12 - 12 - 4 = 0xFFFFFFFC (wraps in uint32)
    //  Zero-extended to AP4_LargeSize (uint64): 0x00000000FFFFFFFC (~4 GB)

    while (entry_count--) {
        AP4_Atom* atom;
        while (AP4_SUCCEEDED(atom_factory.CreateAtomFromStream(
                                 stream, bytes_available, atom))) {
            m_Children.Add(atom);  // out-of-bounds atoms become dref children
        }
    }
}
```

**Guard in `Create()`**:  
```cpp
if (size < AP4_FULL_ATOM_HEADER_SIZE) return NULL;  // AP4_FULL_ATOM_HEADER_SIZE = 12
```
The guard accepts `size = 12`, but by that point the stream has already consumed
8 bytes (atom header) + 4 bytes (version/flags via `ReadFullHeader`) = 12 bytes.
The constructor then reads 4 more bytes for `entry_count` from **outside** the dref
boundary, and `12 - 12 - 4 = 0xFFFFFFFC` wraps.

## Attack Path

```
mp42aac(input.mp4)
  → AP4_File constructor
  → AP4_AtomFactory::CreateAtomsFromStream (moov/trak/mdia/minf/dinf hierarchy)
  → CreateAtomFromStream sees dref with size=12
  → AP4_DrefAtom::Create(size=12, ...)
       guard: 12 >= 12  → PASS (bug: should check size >= 16)
       ReadFullHeader reads 4 bytes (version/flags)
  → AP4_DrefAtom::AP4_DrefAtom(size=12, ...)
       stream.ReadUI32(entry_count)  ← reads 4 bytes OUTSIDE dref boundary
       bytes_available = 12 - 12 - 4 = 0xFFFFFFFC  ← UNDERFLOW
       inner while loop: CreateAtomFromStream(stream, 0xFFFFFFFC, atom)
         ← accepts any atom ≤ 4 GB, reads deep beyond dref boundary
```

## PoC Construction

The crafted MP4 contains a valid-enough structure (ftyp, moov, mvhd, trak,
tkhd, mdia, mdhd, hdlr, minf, smhd) to reach the dinf/dref parsing code.

Inside the `dinf` box (44 bytes total):

| Offset | Bytes | Field |
|--------|-------|-------|
| 0      | `00 00 00 2C` | dinf size = 44 |
| 4      | `64 69 6E 66` | "dinf" |
| 8      | `00 00 00 0C` | **dref size = 12** (trigger!) |
| 12     | `64 72 65 66` | "dref" |
| 16     | `00 00 00 00` | version=0, flags=0 |
| — dref boundary — dref claims only 12 bytes (offset 8..19) — |
| 20     | `00 00 00 01` | entry_count=1 (read by constructor from outside dref) |
| 24     | `00 00 00 0C` | url atom size=12 |
| 28     | `75 72 6C 20` | "url " |
| 32     | `00 00 00 01` | version=0, flags=1 (self-contained) |
| 36     | `FF FF FF E0` | large fake atom size (~4 GB) |
| 40     | `75 72 6C 20` | "url " |

**Execution flow with `dref size=12`**:

1. `Create()` guard passes (12 >= 12).
2. `ReadFullHeader()` consumes bytes 16-19 (version/flags), stream at byte 20.
3. Constructor reads `entry_count` from bytes 20-23 → `entry_count = 1`.
4. Line 81: `bytes_available = 12 - 12 - 4 = 0xFFFFFFFC`.
5. Inner while loop iteration 1:
   - `CreateAtomFromStream` reads url atom at bytes 24-35 (size=12 ≤ 0xFFFFFFFC).
   - Atom added to `m_Children`; bytes_available -= 12 → 0xFFFFFFF0.
6. Inner while loop iteration 2:
   - `CreateAtomFromStream` reads fake atom at bytes 36-43 (size=0xFFFFFFE0 ≤ 0xFFFFFFF0).
   - `stream.Seek(start + 0xFFFFFFE0)` → seeks ~4 GB past current position.
   - `Seek` fails (beyond EOF) → function deletes atom and returns error.
7. Inner while exits. Outer loop (entry_count--) sets count to 0, exits.

The stream position desync (caused by dref reading 8 extra bytes from outside its
boundary before `CreateAtomFromStream` reseeks to `dref_start + 12`) also means
the dinf container will re-parse the attacker-controlled bytes as a new child atom
when it resumes scanning after dref.

## Expected Sanitizer Output

- **ASAN**: may report heap-use-after-free or out-of-bounds if any subsequent
  atom parser accesses a buffer using the corrupted `bytes_available` or the
  stream position desync causes a read beyond an allocated buffer.
- **UBSAN** (`-fsanitize=undefined`): does NOT report unsigned wraparound by
  default (unsigned arithmetic is defined C++ behavior). Would report if any
  signed overflow or null-dereference arises from the corrupted parsing state.
- **Worst case**: process exits non-zero due to cascading parse errors (no
  explicit sanitizer message, but the vulnerability is still demonstrated by
  the code path being reached).

## Remediation

Fix in `AP4_DrefAtom::Create()` — raise the minimum size guard:

```cpp
// Before:
if (size < AP4_FULL_ATOM_HEADER_SIZE) return NULL;  // allows size = 12

// After:
if (size < AP4_FULL_ATOM_HEADER_SIZE + 4) return NULL;  // require room for entry_count
```

Or fix in the constructor by guarding the subtraction:

```cpp
if (size <= AP4_FULL_ATOM_HEADER_SIZE + 4) {
    return;  // degenerate box, nothing to parse
}
AP4_LargeSize bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 4;
```
