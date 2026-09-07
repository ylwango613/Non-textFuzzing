# VULN 002 PoC Notes

## Vulnerability Summary

**Location**: `Bento4/Source/C++/Core/Ap4Stz2Atom.cpp`, constructor
`AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)`

**Root Cause**: Integer overflow in `table_size` calculation (line 90) when `sample_count` is
large and `field_size=8`. The product overflows 32-bit unsigned arithmetic to a tiny value,
bypassing the downstream size-guard check.

## Trigger Conditions

- `field_size = 8`
- `sample_count = 0x20000001`

**Overflow**: `table_size = (0x20000001 * 8 + 7) / 8`
- The multiplication `0x20000001 * 8 = 0x100000008` overflows `unsigned int` (32-bit) to `0x00000008`.
- `(0x00000008 + 7) / 8 = 1` — `table_size` becomes 1 instead of the expected ~512 MB.

## Exploitation Path

1. `m_Entries.SetItemCount(0x20000001)` — attempts to allocate an array of ~536 million UI08 entries
   (~512 MB). On systems without enough memory this triggers `std::bad_alloc` / OOM crash.
   On systems with large overcommit, it may succeed.

2. `(table_size + 8) > size` → `9 > 20` → **false** — guard is bypassed due to overflow.

3. `new unsigned char[table_size]` → allocates only 1 byte (`buffer`).

4. `stream.Read(buffer, 1)` — reads 1 byte from the stream (could be start of the next atom).

5. The `case 8` loop runs for all 0x20000001 iterations:
   ```
   for (unsigned int i = 0; i < sample_count; i++)
       m_Entries[i] = buffer[i];   // buffer is only 1 byte → heap buffer over-read
   ```
   `buffer[i]` for `i > 0` reads beyond the 1-byte allocation — **heap buffer over-read**
   with potential for information disclosure or crash.

## MP4 Structure

```
ftyp (16 bytes)
moov
  mvhd (108 bytes)
  trak
    tkhd (92 bytes)
    mdia
      mdhd (32 bytes)
      hdlr (33 bytes)  handler_type='soun'
      minf
        smhd (16 bytes)
        dinf
          dref (28 bytes)  url entry flags=1 (self-contained)
        stbl
          stsd (16 bytes)  entry_count=0
          stts (16 bytes)  entry_count=0
          stsc (16 bytes)  entry_count=0
          stz2 (20 bytes)  *** MALICIOUS: field_size=8, sample_count=0x20000001 ***
          stco (16 bytes)  entry_count=0
```

## Expected Behaviour

| Scenario | Outcome |
|---|---|
| System with ASAN + memory limits | Heap-buffer-overflow / bad_alloc reported |
| Default build (no ASAN) | Crash (SIGSEGV or SIGABRT) or silent corruption |
| System with large overcommit | OOM killer or heap over-read crash |

The most likely immediate symptom is a `std::bad_alloc` inside `AP4_Array::SetItemCount`
when trying to allocate 0x20000001 entries, or an ASAN heap-buffer-overflow report when
the over-read of `buffer` is detected.

## Files

| File | Purpose |
|---|---|
| `vuln_002_gen.py` | Generates `vuln_002.mp4` |
| `vuln_002_run.sh` | Runs the binary and collects output |
| `vuln_002.mp4` | Malicious input file (auto-generated) |
| `vuln_002_result.txt` | Program + ASAN output |
| `vuln_002_status.txt` | Final verdict |
