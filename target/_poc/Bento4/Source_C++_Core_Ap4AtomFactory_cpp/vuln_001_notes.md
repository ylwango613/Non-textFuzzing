# VULN 001 — AP4_CttsAtom 32-bit Integer Overflow Leading to Heap OOB Read

## Vulnerability Summary

- **Component**: Bento4 library, `Ap4CttsAtom.cpp` lines ~79-80
- **Class**: `AP4_CttsAtom` constructor
- **Type**: Integer overflow (32-bit) → heap out-of-bounds read
- **Trigger binary**: `mp42aac`

## Root Cause

In `AP4_CttsAtom::AP4_CttsAtom(...)` the code performs:

```cpp
AP4_UI32 entry_count = ...;  // read from stream
AP4_DataBuffer payload;
payload.SetDataSize(entry_count * 8);  // 32-bit multiplication OVERFLOWS
```

When `entry_count = 0x20000000`:
- `entry_count * 8 = 0x100000000` which wraps to `0` in 32-bit arithmetic
- `payload` is allocated with **0 bytes**

Meanwhile, `m_Entries.SetItemCount(entry_count)` uses 64-bit arithmetic and
allocates approximately 1 GB of memory for the entries array.

The subsequent `for` loop then reads from `payload.GetData()` (a 0-byte buffer)
with `payload[i*8]` for `i` from 0 to `entry_count-1`, causing an out-of-bounds
heap read that ASAN will detect as a `heap-buffer-overflow`.

## Call Chain

```
mp42aac main()
  -> AP4_File::AP4_File()
  -> AP4_AtomFactory::CreateAtomsFromStream()
  -> AP4_AtomFactory::CreateAtomFromStream()
  -> AP4_CttsAtom::Create()
  -> new AP4_CttsAtom(size, version, flags, stream)
       -> payload.SetDataSize(entry_count * 8)  // OVERFLOW: 0x20000000*8 = 0
       -> stream.Read(payload.GetData(), payload.GetDataSize())  // reads 0 bytes
       -> for (i=0; i<entry_count; i++) { ... payload.GetData()[i*8] }  // OOB READ
```

## PoC File Structure

The generated `vuln_001.mp4` contains:

```
ftyp (20 bytes)
moov
  mvhd (version 0)
  trak
    tkhd (version 0)
    mdia
      mdhd (version 0)
      hdlr (soun handler)
      minf
        smhd
        dinf
          dref
        stbl
          stsd
          stts (0 entries)
          ctts (20 bytes — TRIGGER BOX)
            size=20
            type='ctts'
            version=0, flags=0
            entry_count=0x20000000  <-- triggers overflow
          stsc (0 entries)
          stsz (0 entries)
          stco (0 entries)
```

The `ctts` box declares `size=20`, which includes only the box header
(8 bytes) + FullBox fields (4 bytes) + entry_count field (4 bytes) + 4 bytes padding = 20 bytes.
No actual entry data follows, but `entry_count=0x20000000` is parsed and used
to allocate/iterate without bounds.

## Expected Behavior

- **With ASAN**: `heap-buffer-overflow` or `SEGV` on the OOB read inside the `for` loop
- **Without ASAN**: Potential silent data corruption or crash depending on heap layout
- **Memory caveat**: `SetItemCount(0x20000000)` allocates ~1 GB. If the system cannot
  satisfy this allocation, a `std::bad_alloc` exception may be thrown before the OOB
  read is reached, resulting in a different crash path.

## Reproduction

```bash
bash /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_cpp/vuln_001_run.sh
cat /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_cpp/vuln_001_result.txt
```
