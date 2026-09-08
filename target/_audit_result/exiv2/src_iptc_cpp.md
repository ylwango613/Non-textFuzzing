I've now read and analyzed the complete `iptc.cpp` file (all 483 lines) in full detail. Here is my assessment per function group:

**`IptcParser::decode()` (lines 362–419):**
- Loop entry condition `6 <= pEnd - pRead` guarantees at least 6 bytes before any reads.
- Consuming 1 (marker) + 2 (record/dataset) bytes leaves ≥3 bytes; `extTest = *pRead` is safe.
- Standard path: `getUShort` reads bytes [3–4], valid; `pRead += 2` safe.
- Extended path: `getUShort` reads bytes [3–4]; `sizeOfSize > 4` guard eliminates huge sizes; `if (sizeOfSize > pEnd - pRead) return 6` bounds the per-byte reads; maximum accumulated `sizeData` = 0xFFFFFFFF but this is caught by `sizeData <= pEnd - pRead` → returns 7 if insufficient buffer.
- `pRead` never advances past `pEnd`. No OOB possible.

**`IptcParser::encode()` (lines 421–456):**
- Buffer size from `iptcData.size()`: 5 bytes + dataSize for standard; 9 bytes + dataSize for extended. This exactly matches what the write loop produces: 3 (marker/record/tag) + 2 or 6 (size field) + `iter.value().copy(...)`.
- `sortedIptcData` is a deep copy of `iptcData`; sizes are identical.
- Correctness of `Value::size()` == `Value::copy()` is a Value contract issue, not an iptc.cpp bug.

**`IptcData::printStructure()` (lines 278–302):**
- Early return at `bytes.size() < 3` prevents unsigned underflow in `bytes.size() - 3`.
- `bytes.at(i+1)` and `bytes.at(i+2)` are within bounds given `i < bytes.size() - 3`.
- `Internal::enforce()` is called before using `len` as an offset, throwing on violation rather than causing memory corruption.
- `makeSlice(bytes, i+5, i+5+min(40,len))` is bounded by the enforce.

**`IptcData::size()` (lines 219–232):**
- `newSize` is `size_t`; values are bounded by parsed input buffer size; no practical overflow from file-controlled data.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
