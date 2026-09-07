**Summary of analysis:**

**Batch 1 (lines 1-546, full file):**

1. **Negative refnum OOB** (lines 97, 193, 222, 444): `imgFileNames[ref->getRefNum()]` has no lower-bound check. **→ Mitigated:** `Parser.cc:113` validates `num >= 0 && gen >= 0` before `initRef()` — no negative refnum can reach this code.

2. **Integer overflow in bitmap size** (lines 173, 333): `size = height * ((width + 7) / 8)` can overflow for attacker-controlled `width`/`height`. **→ Not exploitable:** reads are bounded to `sizeof(buf) = 4096`; the fixed-size stack buffer cannot overflow regardless of `size` value.

3. **`sizeof(GString)` instead of `sizeof(GString *)`** in `startDoc()` line 62: `gmallocn(imgFileNamesSize, sizeof(GString))` over-allocates (~2x) for a pointer array. **→ Not a vulnerability:** over-allocation is safe; no underflow.

4. **`ImageStream` constructor overflow** (Stream.cc:371-375): explicit `width > INT_MAX / nComps` guard is present — safely handled.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
