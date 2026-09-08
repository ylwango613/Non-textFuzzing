After thorough analysis of `UTF8.h`, `UTF8.cc`, and all related callers, I have completed my review. The code is well-structured:

- `mapUTF8` and `mapUCS2`: correct `bufSize` checks before every write.
- `getUTF8`: per-branch bounds checks are arithmetically correct for 2–6 byte sequences; signed underflow in `getLength()-N` produces a negative bound that prevents access (safe).
- `getUTF16BE` / `getUTF16LE`: initial `*i >= getLength()-1` guard is correct; the lack of low-surrogate validation is a logic issue only, producing no memory corruption.
- `TextString::insert` BOM detection: accesses `getChar(0/1/2)` on short strings, but `GString::resize(0)` allocates a minimum of 8 bytes and null-terminates, so all three accesses fall within the allocated block.
- `AcroFormField::utf8ToUnicode`: two-pass count-then-fill is deterministic; no allocation mismatch possible.
- `UnicodeTypeTable` lookup functions: all guard `c > 0xffff` before array access, safely handling the 5/6-byte legacy UTF-8 codepoints that `getUTF8` can produce.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
