Confirmed: the execution loop at line 407-411 uses `ints.at(nStart++)` and `uint.at(nStart++)` — both `std::vector::at()`, which throw `std::out_of_range` on OOB access. The `uint16_t count` overflow at line 394-398 can bypass the bounds check but cannot cause memory corruption because all actual accesses are through bounds-checked `.at()`. This is DoS only, not a memory safety vulnerability.

All analysis is complete. No externally-triggerable memory safety vulnerabilities were found across `tiffimage_int.cpp` and its full call chain:
- `readTiffEntry()`: multi-layered overflow and bounds protection
- `addElement()`: `std::min` clamping prevents OOB
- `visitDirectory()`: circular IFD detection + `n > 256` cap
- Selector functions: all indices within static bounds
- `nikonCrypt()`/`ncrypt()`: validated start offsets, byte-indexed xlat
- `getPath()` assert UB: encode path only, not reachable from image read

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
