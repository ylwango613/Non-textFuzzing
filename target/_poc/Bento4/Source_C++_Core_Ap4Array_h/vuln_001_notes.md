# VULN-001 PoC Notes: Integer Overflow in AP4_Array::EnsureCapacity

## What the PoC Does

`vuln_001_gen.py` constructs a minimal but structurally valid MP4 file (`vuln_001.mp4`)
containing a `ctts` (Composition Time to Sample) box whose `entry_count` field is set to
`0x20000001` (536870913). The file contains no actual ctts entries — just the malformed header.

When Bento4's `mp42aac` parses this file it reaches:

```
AP4_CttsAtom::AP4_CttsAtom()   [Ap4CttsAtom.cpp:79]
  -> m_Entries.SetItemCount(entry_count)   // entry_count = 0x20000001
    -> AP4_Array<T>::EnsureCapacity(0x20000001)   [Ap4Array.h:172]
      -> ::operator new(0x20000001 * sizeof(AP4_CttsTableEntry))
```

`AP4_CttsTableEntry` is 8 bytes, so the allocation requested is:

```
0x20000001 * 8 = 0x100000008 bytes  (~4 GB on 64-bit)
```

## Actual Crash Mechanism (64-bit ASAN, Linux overcommit)

There are two allocations in `AP4_CttsAtom::AP4_CttsAtom()`:

**Allocation 1 — EnsureCapacity (Ap4Array.h line 172):**
```cpp
T* new_items = (T*) ::operator new (count * sizeof(T));
// count=0x20000001 (uint32_t), sizeof(T)=8 (size_t) → 64-bit arithmetic
// 0x20000001 * 8 = 0x100000008 (~4 GB)
```
On Linux with overcommit, this large virtual allocation SUCCEEDS. The 4 GB of memory is
then zero-initialized by constructing 0x20000001 `AP4_CttsTableEntry` objects.

**Allocation 2 — read buffer (Ap4CttsAtom.cpp line 80) — THE ACTUAL CRASH:**
```cpp
unsigned char* buffer = new unsigned char[entry_count * 8];
// entry_count is AP4_UI32 = uint32_t; 8 is int literal
// Multiplication is in 32-bit unsigned arithmetic:
//   0x20000001 * 8 mod 2^32 = 0x100000008 mod 2^32 = 0x8 = 8
// → only 8 bytes allocated!
```
`stream.Read(buffer, 8)` succeeds (1 real entry of 8 bytes is in the file).
The iteration loop then accesses `buffer[8]` at i=1 — one byte past the end of the
8-byte allocation — triggering **ASAN heap-buffer-overflow**.

ASAN report:
```
==ERROR==: AddressSanitizer: heap-buffer-overflow
READ of size 1 at 0x502000000178 (0 bytes past end of 8-byte region)
in AP4_CttsAtom::AP4_CttsAtom(unsigned int, unsigned char, unsigned int, AP4_ByteStream&)
```

### 32-bit (hypothetical)
Same 32-bit overflow, but the EnsureCapacity multiplication ALSO overflows to a small
value, creating a tiny array. Subsequent writes to `m_Entries` in the loop then overflow
that tiny buffer as well — heap buffer overflow in both read and write paths.

## How to Interpret the Result

- **VERIFIED_CRASH**: `vuln_001_result.txt` shows a crash, `std::bad_alloc`, ASAN
  `==ERROR==`, or non-zero exit with an abort signal. This confirms the vulnerability.
- **UNVERIFIED**: The binary exited cleanly — the parser may have rejected the file
  earlier than expected (e.g., bounds check added upstream). Try a different entry_count.
- **ERROR**: The script or generator itself failed; check Python/shell errors.

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates the crafted MP4 |
| `vuln_001.mp4` | The crafted input file |
| `vuln_001_run.sh` | Runs the binary and captures output |
| `vuln_001_result.txt` | stdout/stderr + ASAN log from the run |
| `asan_001.log.*` | Raw ASAN log files (one per process PID) |
| `vuln_001_status.txt` | Single-word verdict: VERIFIED_CRASH / UNVERIFIED / ERROR |

## References

- Vulnerable code: `Bento4/Source/C++/Core/Ap4Array.h`, line 172, `EnsureCapacity()`
- Trigger site: `Bento4/Source/C++/Core/Ap4CttsAtom.cpp`, line 79
