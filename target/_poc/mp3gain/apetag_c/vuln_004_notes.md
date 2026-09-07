# VULN 004 PoC Notes — NULL Pointer Dereference / heap-buffer-overflow via Missing malloc() Check

## Vulnerability

- **Function**: `ReadMP3APETag()` in `apetag.c`
- **Lines**: 171–175
- **Root cause**: `buff = (char *)malloc(TagLen)` at line 171 has no NULL-check. When `TagLen` is enormous (`0xFFFFFFFF`), the allocation either fails entirely (returning NULL → fread NULL dereference) or ASAN intercepts it and returns a tiny sentinel buffer. Either way, `fread(buff, 1, TagLen - sizeof(T), fp)` at line 172 accesses far beyond the allocated region, causing a crash.

## PoC Construction (`vuln_004_gen.py`)

The crafted file (`vuln_004.mp3`) consists of:
1. **4 minimal fake MPEG1/Layer3 frames** (4 × 417 = 1668 bytes) — enough for mp3gain to open and scan the file for trailing tags.
2. **APEv2 footer (32 bytes)** appended at end:
   - `ID = "APETAGEX"` (required magic)
   - `Version = 2000` (APEv2 required)
   - `Length = 0xFFFFFFFF` — the malicious field; causes `malloc(0xFFFFFFFF)`
   - `ItemCount = 0`, `Flags = 0`, `Reserved = 0x00…`

## Observed Behavior

Under ASAN build (`build_test/mp3gain`):

- **ASAN heap-buffer-overflow in `ReadMP3APETag`**: ASAN intercepted the enormous `malloc(0xFFFFFFFF)`, returned a very small sentinel allocation. Subsequent `fread` or `memcpy` with `TagLen - 32` bytes immediately overflowed that buffer → `heap-buffer-overflow` reported. Stack trace confirms the crash originates inside `ReadMP3APETag`, consistent with the documented vulnerable code path.
- **UBSAN left-shift UB** (`apetag.c:287`): `1 << 31` on a signed `int` is also caught during tag processing.

Without ASAN (plain binary): `malloc(0xFFFFFFFF)` returns NULL; `fread(NULL, ...)` causes a segmentation fault (NULL pointer dereference).

## Files

| File | Purpose |
|------|---------|
| `vuln_004_gen.py` | Generates the malicious `vuln_004.mp3` |
| `vuln_004.mp3` | Crafted input: 4 fake MP3 frames + APEv2 footer (Length=0xFFFFFFFF) |
| `vuln_004_run.sh` | Runs mp3gain under ASAN and captures errors |
| `vuln_004_result.txt` | Captured output: UBSAN + ASAN errors |
| `vuln_004_status.txt` | **VERIFIED_CRASH** |
