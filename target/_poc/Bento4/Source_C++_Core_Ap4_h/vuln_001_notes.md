# VULN 001 – PoC Notes

## Vulnerability Summary
- **Location**: `Bento4/Source/C++/Core/Ap4CttsAtom.cpp`, constructor `AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_ByteStream&)`
- **Class**: Integer Overflow → Heap-based Buffer Overflow (32-bit multiply) / DoS (bad_alloc on 64-bit)

## Trigger Condition
The constructor reads `entry_count` from the stream and calls `m_Entries.SetItemCount(entry_count)` without any bounds check. When `entry_count = 0x20000001`:
- On 32-bit: `0x20000001 * 8 = 8` (overflow), so only 8 bytes are allocated while the array is treated as if it holds ~536M entries → heap buffer overflow on subsequent writes.
- On 64-bit: the 64-bit `EnsureCapacity` computes the correct (huge) size `~4 GB`, which causes `std::bad_alloc` → crash / DoS.

## PoC Strategy
1. Build a structurally valid MP4 with the minimal required box hierarchy: `ftyp → moov → trak → mdia → minf → stbl → ctts`.
2. All surrounding boxes (mvhd, tkhd, mdhd, hdlr, smhd, dinf/dref, stsd, stts, stsc, stsz, stco) are filled with zero/minimal data so the parser reaches the `ctts` box without early rejection.
3. The `ctts` FullBox is crafted to be exactly 16 bytes: 8-byte box header + 4-byte version/flags + 4-byte `entry_count=0x20000001`. No actual entries follow — the size field says 16 so the stream moves on immediately after the count is read.
4. `mp42aac` opens the file via `new AP4_File(*input)`, which traverses the atom factory and calls `AP4_CttsAtom::Create`, reaching the vulnerable constructor.

## Expected Behavior
- **64-bit build**: `std::bad_alloc` thrown inside `AP4_Array::EnsureCapacity`, propagated as unhandled exception → process terminates (SIGABRT or similar).
- **ASAN build**: may additionally report heap-buffer-overflow if 32-bit path is taken, or simply the terminate signal.
- **Observable result**: non-zero exit code from `mp42aac`, possible ASAN log entries referencing `AP4_CttsAtom` or `AP4_Array`.

## Files
| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Generates `vuln_001.mp4` |
| `vuln_001.mp4` | Malicious input (ctts entry_count=0x20000001) |
| `vuln_001_run.sh` | Runs binary and captures output |
| `vuln_001_result.txt` | stdout/stderr + ASAN log (generated at runtime) |
| `vuln_001_status.txt` | Verification result |
