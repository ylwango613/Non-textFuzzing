I've now read the complete `futils.cpp` (431 lines) in full and traced all call sites. Let me verify the one subtle candidate — the `decoding_table` in `base64decode` — and the `urldecode` boundary condition before rendering a final verdict.

**Key findings from the analysis:**

**`urldecode` (lines 129–147):** Accesses `str[idxIn+1]` and `str[idxIn+2]` without explicit bounds checks. However, C++ guarantees `str[size()]` returns '\0' (the null terminator). Short-circuit evaluation ensures `str[idxIn+2]` is only reached when `str[idxIn+1]` is truthy (non-null), which implies `idxIn+1 < sizeStr`, so `idxIn+2 ≤ sizeStr`, at most touching the defined null terminator. No OOB.

**`base64decode` (lines 178–218):** `decoding_table[256]` is only partially initialized (64 of 256 entries). Non-base64 input bytes read uninitialized stack memory — this is UB — but the index is always 0–255 (unsigned char), so no OOB read occurs, and output writes are bounded by `j < output_length` guards. Memory-safe.

**`base64encode` (line 153):** `output_length = 4 * ((dataLength + 2) / 3)` can overflow if `dataLength ≈ SIZE_MAX`, but callers in `basicio.cpp` derive `size` from real file I/O, making this unreachable in practice.

**`basicio.cpp:963–964` (`base64decode` caller):** Buffer = `data.length()` bytes; decoded output is always ≤ ¾ × input, so the `output_length + 1 < out_size` guard holds. No OOB.

**URI parsing / process path functions:** No unsafe indexing, pointer arithmetic, or recursion.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
