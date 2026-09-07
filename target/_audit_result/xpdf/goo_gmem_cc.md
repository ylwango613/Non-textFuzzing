I have now fully read and analyzed `gmem.cc` (397 lines) and its companion `gmempp.cc`. Let me summarize my findings by section:

**Batch 1 (lines 1–153): `gmalloc`**
- Production path: checks `size < 0` and `size == 0`, then calls `malloc(size)`. The `int→size_t` implicit conversion in `malloc` is safe for positive values. No overflow.
- DEBUG_MEM path: `size1 = gMemDataSize(size)`, then `malloc(size1 + gMemHdrSize + gMemTrlSize)`. When `size` approaches INT_MAX, `size1 + gMemHdrSize + gMemTrlSize` could overflow — but this is debug-only code, not active in production.

**Batch 2 (lines 155–215): `grealloc`, `gmallocn`**
- `grealloc`: Same negative/zero guards, delegates to `realloc`/`malloc`. Safe.
- `gmallocn`: Overflow check `nObjs >= INT_MAX / objSize` correctly prevents signed integer overflow in `n = nObjs * objSize`. Safe.

**Batch 3 (lines 217–305): `gmalloc64`, `gmallocn64`, `greallocn`**
- `gmalloc64`: Takes `size_t`, calls `malloc(size)`. No narrowing, no overflow.
- `gmallocn64`: Check `(size_t)nObjs >= SIZE_MAX / objSize` correctly gates the multiplication. Safe.
- `greallocn`: Same overflow check as `gmallocn`. Safe.

**Batch 4 (lines 307–397): `gfree`, `gMemError`, `gMemReport`, `copyString`**
- `copyString`: `gmalloc((int)strlen(s) + 1)` — if `strlen(s) ≥ INT_MAX`, the cast truncates and `+1` causes signed overflow UB, ultimately reaching `gmalloc` with a negative value → `gMemError` → process exit. DoS only; heap overflow is not achievable since the string itself would need to be ≥2GB in process memory.

**`gmempp.cc`**: `operator new(size_t size)` calls `gmalloc((int)size, ...)` — truncating `size_t→int`. However, this entire file is gated by `#ifdef DEBUG_MEM`, so it is inactive in production builds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
