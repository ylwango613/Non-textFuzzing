The `LocalParams.h`/`LocalParams.cc` is a trivial 40-line wrapper class:
- Two POD fields: an enum (`GfxRenderingIntent`) and a `GBool`
- Constructor initializes both to safe constants
- Destructor is empty (no heap resources)
- All getters/setters are inline one-liners with no pointer arithmetic, no buffer ops, no allocations

No file-supplied values reach this class directly, no dynamic memory is involved, and no array indexing or pointer arithmetic is present. There are no memory safety vulnerabilities here.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
