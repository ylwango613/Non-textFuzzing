# VULN 001 Notes: NULL Pointer Dereference via Unchecked malloc in WebP Chunk Reading

## Vulnerability

- **Function**: `ReadWebpSections()` in `webpfile.c`, lines 99-104
- **CWE**: CWE-476 (NULL Pointer Dereference)

## Root Cause

In `ReadWebpSections()`, each WebP chunk's 4-byte little-endian length is read from the file and padded to an even number of bytes:

```c
unsigned int ReadLen = (ChunkLen + 1) & ~1;   // line 99
uchar * Data = (uchar *)malloc(ReadLen);        // line 101
if (fread(Data, 1, ReadLen, infile) != ReadLen) { // line 102
    free(Data);
    break;
}
```

When `ChunkLen = 0x7FFFFFFF`:
- `ReadLen = (0x7FFFFFFF + 1) & ~1 = 0x80000000` (2 GB)
- `malloc(0x80000000)` fails on a normal system and returns `NULL`
- `fread(NULL, 1, 0x80000000, infile)` dereferences the NULL pointer → **SIGSEGV**

The guard at line 89 (`if ((int)ChunkLen <= 0) continue;`) does **not** protect against this because `(int)0x7FFFFFFF = 2147483647`, which is positive and passes the check.

## PoC Approach

`vuln_001_gen.py` constructs a minimal RIFF/WEBP file:
- 12-byte RIFF header: `"RIFF"` + LE file size + `"WEBP"`
- One malicious chunk: `"EXIF"` FourCC + length `0x7FFFFFFF` (LE)
- No actual chunk data (the crash occurs before any data is read)

The file is written as `vuln_001_input.jpg` (jhead accepts various extensions).

## Trigger Path

```
jhead main()
  -> ReadImgFile()
     -> ReadWebpSections()
        -> Get32webp() returns 0x7FFFFFFF
        -> ReadLen = 0x80000000
        -> malloc(0x80000000) returns NULL
        -> fread(NULL, ...) -> SIGSEGV / ASAN heap-buffer-or-null report
```

## System-Specific Considerations

The test system has 1 TB of RAM with memory overcommit enabled (`/proc/sys/vm/overcommit_memory = 0`). On such a machine `malloc(2 GB)` succeeds via virtual-memory overcommit, so the NULL-pointer path cannot be triggered by RAM pressure alone.

Two file-crafting details compensate:

1. **Force malloc failure**: Run jhead with `ASAN_OPTIONS=max_allocation_size_mb=512`. ASAN's allocator rejects the 2 GB request and (with `allocator_may_return_null=1`) returns NULL, printing a warning.

2. **Ensure fread has data to write**: The crafted file includes 32 padding bytes after the chunk header. Without them the file is at EOF when `fread(NULL,...)` is called, so glibc returns 0 before touching the NULL buffer. With padding bytes present, glibc's `_IO_file_xsgetn` tries to memcpy into the NULL buffer and faults.

## Expected Behavior

With ASAN+UBSAN enabled and `ASAN_OPTIONS=max_allocation_size_mb=512:allocator_may_return_null=1`, the process aborts with:

```
WARNING: AddressSanitizer failed to allocate 0x80000000 bytes
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a WRITE memory access.
  #0 ... (libc fread/xsgetn)
  #1 ... ReadWebpSections
  #2 ... ReadImgFile
  #3 ... main
```
