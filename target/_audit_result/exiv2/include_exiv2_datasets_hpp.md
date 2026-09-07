After complete analysis of all relevant files, I have traced every data flow from external file input through `datasets.hpp`/`datasets.cpp` → `iptc.cpp` → `photoshop.cpp` → `value.cpp`:

**Group 1 — datasets.hpp / datasets.cpp (lines 1–600):**
- `dataSetIdx()` loops are always terminated by the `0xffff` sentinel; `records_[]` is only indexed with validated values `envelope=1` / `application2=2`. No OOB.
- All `dataSetXxx()` helpers handle unknown recordId/number by returning sentinel values. No OOB.

**Group 2 — iptc.cpp IptcParser::decode (lines 362–419):**
- Loop guard `while (6 <= static_cast<size_t>(pEnd - pRead))` guarantees ≥6 bytes before any field is consumed; pRead never advances past pEnd in any branch.
- Extended-dataset path: `sizeOfSize` capped at 4; `if (sizeOfSize > pEnd - pRead) return 6` guards the accumulation loop.
- `if (sizeData <= static_cast<size_t>(pEnd - pRead))` guards the data read + subsequent `pRead += sizeData`.
- The `*pRead++ << (8*(sizeOfSize-1))` with sizeOfSize=4 is technically signed-integer UB (byte→int promotion, shift overflows for values ≥0x80), but produces correct results on all supported targets and is not exploitable.

**Group 3 — photoshop.cpp Photoshop::locateIrb (lines 54–123):**
- `byte psSize = pPsData[position] + 1; psSize += (psSize & 1);` wraps to 0 for Pascal-string length bytes 0xFE or 0xFF (uint8_t arithmetic overflow). This causes `position` not to advance past the Pascal string — a real logic bug.
- However: `dataSize` is then read from the wrong offset but the subsequent `if (dataSize > (sizePsData - position)) return -2;` bounds check prevents OOB access.
- The wrong `sizeHdr = psSize + 10 = 10` returned to callers causes IPTC data to be read from an incorrect offset, but callers validate bounds independently before any memory operation.
- `pCur = record + sizeHdr + sizeIptc + (sizeIptc & 1)` may advance pCur up to pEnd+1 in edge cases; the loop guard `pCur < pEnd` exits before any dereference. No OOB.

**Group 4 — value.cpp ValueType<T>::read / copy:**
- `len` is validated sizeData from decode; the loop `for (size_t i = 0; i < len; i += ts)` reads at most `len` bytes. No OOB.
- `IptcData::size()` + `IptcParser::encode` allocation and write sizes are consistent; no write-past-end.

**Group 5 — iptc.cpp IptcData::printStructure (lines 278–302):**
- `Slice::at()` calls `rangeCheck()` and throws `std::out_of_range` on any OOB index — exception-based DoS, not memory corruption.
- `Internal::enforce(bytes.size() - i >= 5 + len, ...)` protects the data-copy.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
