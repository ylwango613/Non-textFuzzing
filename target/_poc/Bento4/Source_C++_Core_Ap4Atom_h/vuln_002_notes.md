# VULN 002: AP4_CttsAtom Integer Overflow → Heap OOB Read

## Vulnerability Summary

**Binary**: `mp42aac` (Bento4)
**File**: `Ap4CttsAtom.cpp`, lines 77–98
**Function**: `AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)`
**CWE**: CWE-190 (Integer Overflow) → CWE-125 (Out-of-Bounds Read)

## Root Cause

The `ctts` (Composition Time-to-Sample) atom constructor reads `entry_count` directly from the file and uses it in an allocation without overflow checking:

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);
AP4_DataBuffer buffer(entry_count * 8);  // OVERFLOW: entry_count * 8
stream.Read(buffer.UseData(), entry_count * 8);
```

When `entry_count = 0x20000000` (536,870,912):
- `entry_count * 8 = 0x100000000`
- This wraps to **0** in 32-bit arithmetic
- A **zero-byte buffer** is allocated
- The subsequent loop reading `buffer[i*8]` for `i >= 2` reads **beyond the allocation**

## PoC Approach

`vuln_002_gen.py` constructs a minimal but structurally valid MP4 file using only Python's `struct` module. The file hierarchy required to reach the `ctts` parser is:

```
ftyp
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr
      minf
        smhd
        dinf
          dref
            url
        stbl
          stsd
          stts
          stsc
          stsz
          stco
          ctts  <-- TRIGGER: entry_count = 0x20000000
```

The `ctts` box payload contains only the 4-byte `entry_count` field set to `0x20000000`. No actual entry data follows, making the box short — the parser will still attempt to allocate and read based on `entry_count`.

## Expected Outcomes

1. **With ASAN (memory available)**: ASAN reports a heap-buffer-overflow or OOB read when the loop accesses `buffer[i*8]` beyond the zero-byte allocation.

2. **Without sufficient RAM**: The `SetItemCount(0x20000000)` call for the entries array may throw `std::bad_alloc`, causing a crash/DoS without the OOB read. ASAN may still report this as an unusual termination.

3. **Timeout**: Allocating or initializing arrays sized for 536M entries may take significant time or memory, causing a timeout — which is itself evidence of the resource exhaustion DoS variant.

## Files

| File | Description |
|------|-------------|
| `vuln_002_gen.py` | Generates the malicious `vuln_002.mp4` |
| `vuln_002_run.sh` | Runs the PoC and collects ASAN output |
| `vuln_002.mp4` | The generated malicious MP4 file |
| `vuln_002_result.txt` | Combined stdout/stderr and ASAN logs |
| `vuln_002_status.txt` | One-line verdict: VERIFIED_CRASH / UNVERIFIED / ERROR / SKIPPED |
| `asan.log.*` | Raw ASAN log files (if any) |
