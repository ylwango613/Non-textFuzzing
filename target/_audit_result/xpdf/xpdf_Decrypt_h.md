I've now completed a thorough, multi-pass read of Decrypt.h (all 129 lines), Decrypt.cc (all ~1617 lines), and the surrounding context (SecurityHandler.cc, XRef.h, Parser.cc). Let me summarize each area I investigated and why it is or isn't a bug.

**Group 1: `DecryptStream` constructor — `objKey[32]` OOB write candidate (lines 341–374)**
For `cryptAES`, 9 bytes are appended to `objKey[keyLength]..objKey[keyLength+8]`. If `keyLength >= 24`, index 32+ is accessed. However SecurityHandler.cc line 272 explicitly clamps `fileKeyLength <= 16` for all RC4/AES-128 paths, and then that value flows through XRef.cc into `DecryptStream`. Result: `keyLength + 8 <= 24 < 32` always. **SAFE.**

**Group 2: `r6Hash` `key1` stack buffer sizing (lines 192–243)**
Buffer declared as `Guchar key1[64*(127+64+48)]` = 15296 bytes. Maximum `n` per iteration = `127 + 64 + 48 = 239`, `n * 64 = 15296`. The tiling loop's last write is `key1[63*239 + 239 - 1] = key1[15295]`. Exactly fits. AES encryption loop and SHA calls all stay within this bound. **SAFE.**

**Group 3: `makeFileKey2` integer-overflow in `gmalloc` (line 259)**
`gmalloc(72 + fileID->getLength())` — theoretical overflow if `fileID` length approaches `INT_MAX`, but would require a ~2 GB PDF. Not practically triggerable. **SAFE (not practical).**

**Group 4: `makeFileKey` R=5/6 out-of-bounds reads (lines 61–88)**
`ownerKey->getCString() + 32` / `+40` / `userKey->getCString()` reading 8/8/48 bytes. SecurityHandler.cc validates `ownerKey.length >= 48` and `userKey.length >= 48` before these calls. **SAFE.**

**Group 5: SHA-256/384/512 internal buffers (lines 1297–1616)**
`blkLen = msgLen % blocksize` is always < blocksize before `blk[blkLen++] = 0x80`, so the write at the highest index (e.g., `blk[127]` for SHA-512) stays within the 128-byte `blk` buffer. **SAFE.**

**Group 6: AES decrypt PKCS7 padding (lines 884–895)**
`n = buf[15]` with validation `if (n < 1 || n > 16) n = 16`. Loop `for (i = 15; i >= n; --i) buf[i] = buf[i-n]` accesses `buf[n..15]` and `buf[0..15-n]`, all within `buf[16]`. **SAFE.**

**Group 7: RC4 key scheduling (`rc4InitKey` with `keyLen = 0`)**
Would cause division-by-zero, but SecurityHandler.cc clamps `fileKeyLength > 0`, so `keyLength >= 1` always. **SAFE.**

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
