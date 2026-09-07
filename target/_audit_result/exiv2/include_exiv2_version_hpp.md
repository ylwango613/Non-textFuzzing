The file `version.hpp` is a 107-line pure header declaring version macros and function prototypes. The implementation in `version.cpp` covers:

- Compile-time constant lookups (`versionNumber`, `versionString`, `testVersion`) — all safe
- `dumpLibraryInfo()` invoked only via `exiv2 --version --verbose` (app/exiv2.cpp:229), never from image-parsing paths
- Windows `handles[200]` OOB-read potential (if > 200 modules loaded) — not triggerable by a crafted image file
- MSVC `editions[edition]` off-by-one at index 16 — compile-time constant, not externally controllable

No image-file-parsing logic exists anywhere in this file or its implementation. All data flows are from compile-time constants or system API calls, with no attacker-controlled bytes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
