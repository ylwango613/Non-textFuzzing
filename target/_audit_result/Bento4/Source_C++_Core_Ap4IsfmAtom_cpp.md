**Analysis summary:**

`Ap4IsfmAtom.cpp` is 131 lines. Complete analysis:

- **`Create()` (L43-52)**: Guards `size >= AP4_FULL_ATOM_HEADER_SIZE` (12 bytes), reads 4 bytes of full header (version+flags), then delegates to the private constructor. `size_32` comes from the factory after atom_is_large is rejected (L604).

- **Private constructor (L70-83)**: Reads exactly 3 bytes from stream into fixed-size `AP4_UI08` member fields (`m_SelectiveEncryption` from 1 byte, `m_KeyIndicatorLength`, `m_IvLength`). No heap allocation, no array indexing, no pointer arithmetic based on file values. Even if `size == 12` (header only), the stream reads fail gracefully into 1-byte stack slots — no memory corruption possible.

- **Downstream consumers** (`Ap4IsmaCryp.cpp`): `m_IvLength`/`m_KeyIndicatorLength` are used in `GetDecryptedSampleSize` and `DecryptSampleData`. In `DecryptSampleData`, `header_size > in_size` is checked before any buffer access (L167). The `bso_bytes[8-m_IvLength]` CopyMemory is guarded by `m_IvLength <= 8` check (L199). The `zero_enc[offset+i]` loop (L214) has a logical bug (`chunk=offset` instead of `chunk=16-offset`) but requires the ISMA decryption path — not exercised by `mp42aac` which only extracts raw audio.

No memory safety vulnerabilities are present in this file or its direct functional context.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
