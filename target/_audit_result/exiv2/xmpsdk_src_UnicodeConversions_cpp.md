I have now read the entire 1,665-line file in three complete passes and traced all key code paths:

**Group 1 (lines 1-450) — initialization, wrapper functions (`ToUTF16`, `ToUTF32`, `FromUTF16`, `FromUTF32`):**  
All wrappers use fixed-size stack buffers (`kBufferSize` of 4 k–16 k units) and pass the size to the converter. The per-chunk `append` writes are bounded by that same `writeCount ≤ kBufferSize`. The `reserve(2*utf8Len)` hint can overflow `size_t` on huge inputs but is just a hint; subsequent `append` calls work correctly regardless. No memory safety issue.

**Group 2 (lines 451-600) — `CodePoint_to_UTF8_Multi` / `CodePoint_from_UTF8_Multi`:**  
`CodePoint_to_UTF8_Multi` computes `bytesNeeded` (result is 2–4 for all valid BMP/SMP code points), then guards with `if (bytesNeeded > utf8Len) goto Done` before writing any byte. Write indices are 0…unitCount-1, all within the checked limit. `CodePoint_from_UTF8_Multi` validates `2 ≤ bytesNeeded ≤ 4`, checks `bytesNeeded ≤ utf8Len` before reading continuation bytes, and rejects surrogate code points explicitly. No OOB access possible.

**Group 3 (lines 695-1020) — `UTF8_to_UTF16Nat`, `UTF8_to_UTF32Nat`, `UTF16Nat_to_UTF8`, `UTF32Nat_to_UTF8`, `UTF16Nat_to_UTF32Nat`, `UTF32Nat_to_UTF16Nat`:**  
All use the standard "track utf*Left remaining" idiom. Every write checks `utf*Left > 0` via the outer while loop. Surrogate pair paths check `utf16Left ≥ 2` inside `CodePoint_to_UTF16Nat_Surrogate` before emitting two units, and the result `len == 0` check propagates correctly. No OOB.

**Group 4 (lines 1023-1665) — Swapped variants:**  
Identical structure to the native variants; the byte-swap helpers operate on individual scalar values, not buffers. The `swap32to16Offset` type-pun reads within a valid 4-byte `UTF32Unit`. No OOB.

**Dead code at line 499:** The second `if (utf8Len == 0) goto Done;` inside `CodePoint_to_UTF8` is unreachable (identical check already done at line 496). A logic error but not a memory safety defect.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
