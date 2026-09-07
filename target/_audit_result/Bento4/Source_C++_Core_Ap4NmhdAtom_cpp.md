`Ap4NmhdAtom.cpp` is 77 lines. The `nmhd` (Null Media Header) box carries no payload fields—only the standard full-atom header (version + flags). The implementation:

- `Create()`: guards `size < AP4_FULL_ATOM_HEADER_SIZE` (12), reads version/flags via `ReadFullHeader`, rejects version ≠ 0, constructs the object.
- Private constructor: passes size/version/flags to the `AP4_Atom` base class; the stream parameter is explicitly unused (`/* stream */`).
- `WriteFields()`: no-op, returns `AP4_SUCCESS`.

There are no dynamic allocations, no array indexing, no buffer reads/writes, and no integer arithmetic in this file. No memory-safety vulnerabilities are present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
