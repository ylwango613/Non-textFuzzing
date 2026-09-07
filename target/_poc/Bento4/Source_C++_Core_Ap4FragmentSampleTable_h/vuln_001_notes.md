# VULN 001 Notes: Integer Overflow in AP4_Array::EnsureCapacity via trun sample_count

## What the Vulnerability Is

`AP4_Array<T>::EnsureCapacity` allocates memory for array elements using the computation:
```
new_size = count * sizeof(T)
```
On 32-bit targets, if `count = 0x10000000` and `sizeof(T) = 16` (size of `AP4_TrunAtom::Entry`), then:
```
0x10000000 * 16 = 0x100000000 = 0 (32-bit overflow)
```
This causes `::operator new(0)` to return a tiny (or NULL-equivalent) buffer, after which `0x10000000` placement-new constructions occur out of bounds, resulting in a heap buffer overflow.

On 64-bit targets (like this binary), the multiplication does not overflow since operands are promoted to 64-bit:
```
0x10000000 * 16 = 0x100000000 = 4GB
```
This causes an OOM/`std::bad_alloc` exception or an extremely large allocation attempt. With ASAN, this may manifest as an allocation failure, OOM abort, or a handled exception rather than a classic heap overflow.

## How the MP4 Triggers It

The crafted `vuln_001.mp4` contains:
1. A valid `ftyp` box to be recognized as an MP4
2. A minimal `moov` box with a sound track and `mvex/trex` (required for fragmented MP4)
3. A `moof` box containing:
   - `mfhd` (movie fragment header)
   - `traf` box with:
     - `tfhd` (track fragment header, track_ID=1)
     - `trun` box with `sample_count = 0x10000000` (268,435,456)

When `mp42aac` parses this file, it reads the `trun` atom and calls `AP4_TrunAtom::Read`, which processes `sample_count = 0x10000000`. The parser then calls `m_Entries.EnsureCapacity(0x10000000)` (or similar), triggering the vulnerable multiplication.

## Expected Behavior by Architecture

### 32-bit target (overflow scenario):
- `EnsureCapacity` computes `0x10000000 * 16 = 0` (overflow)
- Allocates 0 bytes (tiny buffer)
- Begins initializing `0x10000000` entries OOB
- ASAN reports: `heap-buffer-overflow` in `AP4_Array::EnsureCapacity` or `AP4_TrunAtom::Read`

### 64-bit target (this binary, OOM scenario):
- `EnsureCapacity` computes `0x10000000 * 16 = 4GB`
- ASAN/allocator may report: allocation-size-too-large, OOM, or `std::bad_alloc`
- Binary may crash with signal 6 (abort) or exit with a handled error
- ASAN may report: `requested allocation size 0x100000000 exceeds maximum supported size`
