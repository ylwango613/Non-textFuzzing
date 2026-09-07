# VULN 001: Integer Overflow in AP4_Array EnsureCapacity - elst Parser

## Vulnerability Mechanism

`AP4_ElstAtom::AP4_ElstAtom()` (in `Ap4ElstAtom.cpp`) reads `entry_count` as a 32-bit unsigned integer directly from the MP4 stream without any bounds validation. It then calls:

```cpp
m_Entries.EnsureCapacity(entry_count);
```

Inside `AP4_Array::EnsureCapacity()`, the new capacity is computed as:

```cpp
count * sizeof(AP4_ElstEntry)  // 20 bytes per entry
```

- **On 32-bit systems**: with `entry_count = 0x0CCCCCCD`, the multiplication overflows to a small value (e.g., 154 bytes), but `m_AllocatedCount` is set to the original large value. Subsequent `Append()` calls then write beyond the allocated buffer, causing a **heap buffer overflow**.
- **On 64-bit systems**: with `entry_count = 0xFFFFFF00`, the multiplication yields `0xFFFFFF00 * 20 ≈ 3.4 GB`. This triggers `std::bad_alloc` (out-of-memory), causing a **process crash (DoS)**.

The return value of `EnsureCapacity()` is ignored at `Ap4ElstAtom.cpp:73`, so allocation failures go undetected.

There is no upper-bound check such as:
```cpp
if (entry_count > (box_size - header_size) / sizeof(AP4_ElstEntry)) { /* error */ }
```

## Why This MP4 Triggers the Vulnerability

The crafted `vuln_001.mp4` contains a valid MP4 structure (`ftyp` + `moov/trak/edts/elst`) where the `elst` full-box body contains:
- `version = 0`, `flags = 0` (valid full-box header)
- `entry_count = 0xFFFFFF00` (4,294,967,040 entries claimed)
- **No actual entry data** following the count

When `mp42aac` parses the file, it descends into `moov -> trak -> edts -> elst` and invokes `AP4_ElstAtom::Create()`, which calls `new AP4_ElstAtom(...)`. The constructor reads `entry_count = 0xFFFFFF00` from the stream and immediately calls `m_Entries.EnsureCapacity(0xFFFFFF00)`, triggering the vulnerability.

## Expected Behavior

- **On 64-bit ASAN build**: `EnsureCapacity` attempts to allocate ~3.4 GB. The OS refuses the allocation, throwing `std::bad_alloc`. Since this is unhandled, the process terminates abnormally. ASAN may or may not report this, but the crash itself constitutes a **Denial of Service (DoS)**.
- **On 32-bit build**: integer overflow in the multiplication causes a small buffer to be allocated, followed by OOB writes during `Append()` calls, which ASAN would report as a **heap-buffer-overflow**.

The result file (`vuln_001_result.txt`) should show either an ASAN error report, a `std::bad_alloc` termination message, or a non-zero exit code indicating the crash.
