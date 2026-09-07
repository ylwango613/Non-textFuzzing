After thoroughly analyzing `JArithmeticDecoder.h`, `JArithmeticDecoder.cc`, and all callers in `JBIG2Stream.cc` and `JPXStream.cc`, here is my assessment:

**Analysis summary (batch review):**

- `setEntry(Guint cx, ...)`: No bounds check on `cx` vs `contextSize`. All callers use compile-time constants (jpxContextSigProp=0, jpxContextRunLength=17, jpxContextUniform=18) that are < jpxNContexts=19. Not externally triggerable.

- `decodeBit(Guint context, ...)`: Reads and writes `cxTab[context]` without bounds check. Callers maintain invariants: JBIG2 generic decode cx bounded to 16-bit by mask construction; decodeIntBit prev bounded to ≤0x1ff < contextSize=512; decodeIAID prev bounded to 2^codeLen-1 < contextSize=1<<(codeLen+1); JPX cx values 0-18 < jpxNContexts=19. All safe.

- `copyFrom(stats)`: Uses `this->contextSize` with no verification against `stats->contextSize`. Both callers guard with `prevStats->getContextSize() == size` and `this->getContextSize() == size` before calling, ensuring equality.

- `decodeIAID`/`resetIntStats` integer shift UB (`1 << (symCodeLen+1)` when symCodeLen=31): Requires ~2 billion symbols, making the preceding `gmallocn(numSyms, sizeof(JBIG2Bitmap*))` allocation (16 GB) infeasible in practice.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
