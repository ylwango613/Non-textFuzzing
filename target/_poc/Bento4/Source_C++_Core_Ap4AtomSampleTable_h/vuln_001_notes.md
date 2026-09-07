# VULN 001 — AP4_CttsAtom Integer Overflow → Heap Buffer Over-Read

## Vulnerability Summary

**Location:** `Ap4CttsAtom.cpp`, lines 77–97 (AP4_CttsAtom constructor)

**Type:** Integer overflow in `new[]` size calculation leading to heap buffer over-read

## Root Cause

In the `AP4_CttsAtom` constructor, the heap allocation is performed with 32-bit arithmetic:

```cpp
unsigned char* buffer = new unsigned char[entry_count * 8];
```

When `entry_count` is `0x20000001` (an `AP4_UI32`), the multiplication `0x20000001 * 8` overflows a 32-bit integer:

```
0x20000001 * 8 = 0x100000008  →  truncates to 0x8 (only 8 bytes allocated!)
```

However, `m_Entries.SetItemCount(entry_count)` uses 64-bit arithmetic and correctly computes the ~4 GB needed for the entry array.

The subsequent loop:
```cpp
for (unsigned i = 0; i < entry_count; i++) {
    stream.ReadUI32(&buffer[i * 8]);
    ...
}
```

At iteration `i=1`, it writes to `buffer[8]`, which lies beyond the 8-byte allocation — directly into ASAN's red zone — triggering a **heap-buffer-overflow**.

## Trigger Conditions

- A `ctts` box (inside `moov/trak/mdia/minf/stbl/ctts`) with `entry_count = 0x20000001`
- Only 1 actual entry (8 bytes) provided — crash fires at the second read (`i=1`)

## Crash Modes

1. **ASAN heap-buffer-overflow** at `buffer[8]` when ASAN is enabled
2. **`std::bad_alloc`** if `SetItemCount` allocation fails (OOM / 4 GB not available) — still a DoS

## PoC Files

- `vuln_001_gen.py` — generates the malicious `vuln_001.mp4`
- `vuln_001_run.sh` — runs the binary and captures ASAN output
- `vuln_001.mp4` — crafted MP4 with the triggering `ctts` box
