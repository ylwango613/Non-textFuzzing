**Analysis summary:**

- `Ap4IsltAtom.cpp` is 80 lines implementing a fixed-format "iSLT" atom that stores an 8-byte salt.
- The `Create()` factory (header line 47–50) strictly enforces `size == AP4_ATOM_HEADER_SIZE+8` (i.e., exactly 16 bytes) before calling the stream constructor — any other size returns NULL immediately.
- The stream constructor (line 54–59) reads exactly 8 bytes into `m_Salt[8]`, a statically-sized 8-byte member — no dynamic allocation, no file-controlled count, no integer arithmetic on the size.
- `WriteFields` and `InspectFields` also operate on the fixed 8-byte buffer only.
- No `new[]`/`malloc` with file-controlled sizes, no array indexing with file-controlled values, no pointer arithmetic, no UAF patterns.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
