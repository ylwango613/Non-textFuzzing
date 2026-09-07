# VULN 003: AP4_StcoAtom Unsigned Integer Underflow -> OOM Heap Allocation

## Summary

An unsigned integer underflow in `AP4_StcoAtom::AP4_StcoAtom()` bypasses a
bounds check, allowing an attacker-controlled `entry_count` to cause an
enormous heap allocation (up to ~4 GB), resulting in an out-of-memory (OOM)
denial-of-service crash.

## CWE Classification

- **CWE-191**: Integer Underflow (Unsigned)
- **CWE-789**: Memory Allocation with Excessive Size Value

## Affected Files

| File | Lines |
|------|-------|
| `Source/C++/Core/Ap4StcoAtom.cpp` | 78–82 |
| `Source/C++/Core/Ap4Co64Atom.cpp` | 78–81 |

## Root Cause

In `AP4_StcoAtom::AP4_StcoAtom()`:

```cpp
if (m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4) {
    m_EntryCount = 0;
    return;
}
new AP4_UI32[m_EntryCount];  // <- OOM if entry_count is huge
```

`AP4_FULL_ATOM_HEADER_SIZE` = 12 bytes (4 size + 4 type + 1 version + 3 flags).

With `size = 16` (the minimum stco atom that includes the entry_count field):

```
(16 - 12 - 4) / 4 = 0 / 4 = 0
```

The check becomes `m_EntryCount > 0`, which any nonzero entry_count satisfies,
so the check **does not guard against the allocation** as intended. The check
should use `>=` or account for the unsigned subtraction overflow.

With `size = 12` (no room for entry_count):
```
(12 - 12 - 4) / 4  -->  (0 - 4) / 4 (unsigned)  =  0xFFFFFFFC / 4 = 0x3FFFFFFF
```
This allows entry_count up to 1,073,741,823 to pass, an even wider window.

## Trigger

A crafted MP4 file with a `stco` atom where:
- `size = 16`
- `entry_count = 0x10000000` (268,435,456)

Causes `new AP4_UI32[0x10000000]` → 1 GB allocation → OOM crash.

## Trigger Path

```
mp42aac main()
  -> AP4_File constructor
  -> AP4_DefaultAtomFactory::CreateAtomFromStream()
  -> AP4_StcoAtom::Create(size=16, stream)
  -> new AP4_StcoAtom(size=16, version=0, flags=0, stream)
     -> reads entry_count=0x10000000 from stream
     -> bounds check: 0x10000000 > (16-12-4)/4 = 0  -> TRUE, but check is WRONG
     -> new AP4_UI32[0x10000000]  -> ~1 GB allocation -> OOM
```

## PoC Files

| File | Description |
|------|-------------|
| `vuln_003_gen.py` | Python script that constructs the malicious MP4 |
| `vuln_003.mp4` | Generated malicious MP4 file |
| `vuln_003_run.sh` | Shell script that runs the PoC and collects ASAN output |
| `vuln_003_result.txt` | ASAN/runtime output from the run |
| `vuln_003_status.txt` | Verification status |

## Impact

**Denial of Service (DoS)**: Any application using libbento4 to parse
untrusted MP4 files (mp42aac, mp4decrypt, mp4fragment, etc.) can be crashed by
a ~16-byte crafted stco atom embedded in an otherwise valid MP4. No user
interaction beyond opening/processing the file is required.

## Suggested Fix

Replace the bounds check with:

```cpp
AP4_Size payload_size = size - AP4_FULL_ATOM_HEADER_SIZE;
if (payload_size < 4 || m_EntryCount > (payload_size - 4) / 4) {
    m_EntryCount = 0;
    return;
}
```

Or use signed arithmetic / explicit overflow checks before the subtraction.
