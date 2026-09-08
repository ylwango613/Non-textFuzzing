The file `image_int.cpp` is only 13 lines — a single trivial `indent()` function. The header `image_int.hpp` provides two template helpers (`binaryToStringHelper`, `binaryToString`) that use `Slice::at()` for bounds-checked access. All callers explicitly bound the slice size. No DataBuf manipulation, no IFD parsing, no unsafe memory operations exist in this translation unit.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
