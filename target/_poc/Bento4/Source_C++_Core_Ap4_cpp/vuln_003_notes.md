# VULN 003 — AP4_SbgpAtom Bounds-Check Integer Overflow PoC Notes

## Vulnerability Summary

**Location**: `Ap4SbgpAtom.cpp:87` in `AP4_SbgpAtom::AP4_SbgpAtom()`

**Root Cause**: The bounds check uses uint32_t arithmetic:
```cpp
if (remains < entry_count * 8) { ... }  // entry_count is AP4_UI32
```
When `entry_count = 0x20000000`, `entry_count * 8 = 0x100000000` which overflows to `0` in 32-bit arithmetic. The condition `remains < 0` is always false (unsigned comparison), so the bounds check is silently bypassed.

Subsequently, `m_Entries.SetItemCount(entry_count)` attempts to allocate `0x20000000 * sizeof(Entry)` bytes (~4 GB or more), causing a `std::bad_alloc` OOM crash (DoS), or a NULL dereference in nothrow environments.

## PoC Approach

1. Construct a minimal but structurally valid MP4 file that will be parsed deep enough to reach the `sbgp` atom parser.
2. Place a malicious `sbgp` box inside `moov/trak/mdia/minf/stbl/` with `entry_count = 0x20000000`.
3. Add 8 dummy bytes after `entry_count` so that `remains > 0` at the check point, ensuring the overflow condition is exercised rather than an earlier error path.

## sbgp Box Layout (28 bytes total)

```
Offset  Size  Value        Description
0       4     0x0000001C   box size = 28
4       4     73626770     box type = 'sbgp'
8       1     0x00         version = 0
9       3     000000       flags = 0
12      4     726F6C6C     grouping_type = 'roll'
16      4     20000000     entry_count = 0x20000000  ← OVERFLOW TRIGGER
20      8     (zeros)      dummy data (ensures remains = 8 > 0)
```

At the point of the check inside `AP4_SbgpAtom::AP4_SbgpAtom()`:
- `remains = box_data_size - 8 = 20 - 8 = 12`
- `entry_count * 8 = 0x20000000 * 8 = 0` (overflow)
- `12 < 0` → false → bounds check bypassed
- `SetItemCount(0x20000000)` → ~1 GB+ allocation → OOM crash

## Expected Behavior

- **Crash type**: `std::bad_alloc` (OOM) or NULL dereference
- **ASAN output**: May report `out-of-memory` or heap allocation failure
- **Process exit**: Non-zero exit code
- **Impact**: Denial of Service (DoS) via crafted MP4 file
