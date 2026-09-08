After thoroughly reading all ~1,600 lines of `UnicodeConversions.cpp`, `UnicodeInlines.incl_cpp`, and tracing every caller into `XMPCore_Impl.cpp` and `XMPMeta-Parse.cpp`, here is my analysis:

**Key patterns checked:**

1. **`GetCodePoint` hardcoded `utf8Len=4`** (`UnicodeInlines.incl_cpp:23`): Called from `VerifyUTF8` (null-terminated strings) and `VerifySimpleXMLName` (slices of larger strings). Reading up to 4 bytes from valid allocated memory — the bytes past the intended slice boundary are still within the parent C-string allocation. `CodePoint_from_UTF8_Multi` also validates continuation bytes and throws on any malformed sequence, so no exploitable OOB read materializes.

2. **`CodePoint_to_UTF8_Multi` bit math** (`UnicodeConversions.cpp:453-487`): `(cpIn > 0x10FFFF)` guard ensures `bytesNeeded ∈ {2,3,4}`; the `(8-unitCount)` shift is always in `[4,6]`, so no shift UB or integer overflow. The `if (bytesNeeded > utf8Len) goto Done` guard prevents OOB writes.

3. **Outer conversion loops** (`ToUTF16`, `FromUTF16`, etc., lines 273-449): Use fixed 8K/16K stack buffers with their exact sizes passed as `utf16Len`/`utf8Len`. All inner converter functions compute `*utf8Read ≤ utf8Len`, so `utf8Len -= readCount` never underflows.

4. **`CodePoint_from_UTF8_Multi`** (`lines 515-562`): `bytesNeeded > utf8Len` check before any continuation byte reads; no OOB read possible.

5. **Swapped-endian path (`UTF32Swp_to_UTF16Swp`, line 1430)**:
   `*(((UTF16Unit*)utf32Pos) + k32to16Offset)` aliases the 32-bit input as two 16-bit units. This is technically strict-aliasing UB but not a memory-safety issue — it reads within the same 4 bytes already validated to be in-range BMP.

6. **No recursion, no dynamic allocation in hot paths**: No stack-overflow or heap-underallocation risk in this subsystem.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
