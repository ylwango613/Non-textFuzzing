After thorough analysis of the full decode/encode/printStructure paths in `iptc.hpp` and `iptc.cpp`, as well as the callers in `photoshop.cpp`, `tiffvisitor_int.cpp`, `jpgimage.cpp`, and the value type implementations in `value.cpp`:

**Decode path (`IptcParser::decode`):** The loop guard `while (6 <= static_cast<size_t>(pEnd - pRead))` together with the per-path bounds checks (standard: `getUShort` consumes 2 of the guaranteed 3 remaining bytes; extended: `if (sizeOfSize > pEnd - pRead) return 6`) and the final data bounds check `if (sizeData <= static_cast<size_t>(pEnd - pRead))` correctly prevent any OOB read. The UB shift `*pRead++ << (8 * (sizeOfSize - 1))` (signed int overflow when byte ≥ 0x80 and shift = 24) is present but its worst-case effect—producing an unexpectedly large `sizeData`—is absorbed by the subsequent bounds check.

**Encode path (`IptcParser::encode`):** `IptcData::size()` computes exactly `5 + dataSize` (standard) or `9 + dataSize` (extended) per entry; the encoding loop writes exactly the same counts; and all concrete value types (`StringValueBase`, `DataValue`, `ValueType<T>`, `DateValue`, `TimeValue`) have consistent `size()`/`copy()` contracts. No overflow.

**`IptcData::printStructure`:** Two `Internal::enforce` calls gate all array accesses; enforce throws before any OOB can occur.

**No UAF/iterator-invalidation patterns** were found: the decode loop holds only a raw `pRead` pointer into the input buffer, never iterators into `iptcData`, and `IptcData::add()` uses the result of `findId` only before the potential `push_back`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
