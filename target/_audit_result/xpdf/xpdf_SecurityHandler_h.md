The `gmalloc` non-debug path confirms: `if (size < 0) { gMemError(...) }` — an integer-overflow-to-negative in `72 + fileID->getLength()` would hit abort, not produce an undersized allocation.

**Full audit summary of analyzed paths:**

1. **SecurityHandler.h** — pure class declaration, no memory operations.
2. **SecurityHandler.cc constructor** — `fileKeyLength` is always bounded (clamped ≤16 or ≤32 at lines 272–274 / 280–282); ownerKey/userKey padded to 32 bytes for rev≤4; rev 5/6 requires ≥48 bytes (enforced, fatal).
3. **Decrypt::makeFileKey** — `test[183]` correctly fits max(len+56) = 183 bytes; ownerKey/userKey accesses at `+32`, `+40`, `+48` offsets are safe given the length guards above.
4. **Decrypt::r6Hash** — `key1[64*(127+64+48)] = key1[15296]`; maximum post-multiply `n = 64*239 = 15296` — exactly the buffer size (tight but correct); 64*n is always a multiple of 16 so AES block loop is never partial.
5. **Decrypt::makeFileKey2** — `buf = gmalloc(72 + fileID->getLength())`; sum-to-negative would be caught by `gmalloc`'s `size < 0` guard (aborts); all subsequent writes stay within the 72+L allocation.
6. **DecryptStream constructor** — `fileKey[32]`, `objKey[32]` correctly sized; RC4/AES keyLength ≤16, AES256 keyLength ≤32; max indexing within bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
