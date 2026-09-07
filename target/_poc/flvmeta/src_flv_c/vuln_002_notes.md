# VULN 002 PoC Notes
## CWE-476: NULL Pointer Dereference — check.c:659-661

### Vulnerability Summary

In `check_flv_file()` (check.c:659-661):
```c
char * buffer = malloc(amf_string_get_size(name) + 50);
sprintf(buffer, "unknown metadata event name: '%s'", (char*)amf_string_get_bytes(name));
```
`malloc()` return value is never checked. If it returns NULL, `sprintf(NULL, ...)` dereferences
the null pointer, causing a crash (SIGSEGV / SIGABRT).

### Trigger Path

1. FLV file contains a Script tag (type 0x12)
2. The AMF0 string name in the tag is NOT one of: `onMetaData`, `onCuePoint`, `onLastSecond`
3. `check_flv_file()` reaches the `strcmp` block at line 655-657 (all three strcmp return non-zero)
4. `malloc(name_len + 50)` is called — if it returns NULL, `sprintf` crashes

### PoC FLV Construction (`vuln_002.flv`)

Built with Python `struct` only (53 bytes total):

| Section            | Bytes | Description                            |
|--------------------|-------|----------------------------------------|
| FLV Header         | 9     | "FLV" + ver 1 + flags 0x05 + offset 9 |
| PrevTagSize0       | 4     | 0x00000000                             |
| Script tag header  | 11    | type=0x12, size=25, ts=0, sid=0        |
| AMF0 string        | 17    | 0x02 + len(14) + "onCustomFuzzer"      |
| AMF0 ECMA array    | 8     | 0x08 + count(0) + end-tag 0x000009     |
| PrevTagSize1       | 4     | 36 (= 11 + 25)                         |

AMF name `onCustomFuzzer` is 14 chars → `malloc(14 + 50) = malloc(64)` is the
vulnerable call site.

### Run Results

**Normal run** (`flvmeta --check vuln_002.flv`):
- Parses the Script tag successfully
- The `onMetaData event not found` warning confirms the non-standard name was processed
- `malloc(64)` succeeds; `sprintf` writes the info string without crash
- The INFO-level message "unknown metadata event name" is not shown by default
  (INFO messages are filtered unless a higher verbosity is requested)

**ulimit-constrained runs** (attempting to force malloc failure):
- At 40000–30000 KB: ASAN itself fails to reserve its 256 MB shadow map (errno 12)
  and aborts — this is an ASAN infrastructure failure, not the application bug
- At 20000–12000 KB: The binary can't even dlopen its sanitizer shared libraries
- At 25000 KB: ASAN aborts with "unable to mmap AddrHashMap" — again ASAN overhead

**Root cause of non-reproduction**: The ASAN-instrumented binary requires ~250 MB of
virtual address space for shadow memory alone. `ulimit -v` cannot reduce available
VA below the ASAN minimum while still allowing the binary to run. A non-instrumented
build or a real OOM scenario would be needed to force `malloc(64)` to return NULL.

### Why UNVERIFIED (not SKIPPED)

- The code path IS reached: the FLV successfully causes `check.c:659` to be executed
- The vulnerability IS real: no NULL check exists after `malloc()` before `sprintf()`
- Reproduction requires either:
  (a) A production build (no ASAN) running under extreme memory pressure, or
  (b) Intercepting malloc via LD_PRELOAD to return NULL on demand
- The constraint "no C/C++ compilation" prevents option (b)
- Therefore status: UNVERIFIED

### Status
UNVERIFIED — code path reached, vulnerability confirmed in source, crash not reproducible
with the ASAN binary under ulimit due to sanitizer VA overhead.
