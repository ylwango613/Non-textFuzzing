`EXV_HAVE_XMP_TOOLKIT` is a CMake option set to ON only when expat is found (line 19 of `generateConfigFile.cmake`). Since xmpsdk itself depends on expat for XML parsing, xmpsdk is never built without expat — meaning `EXV_HAVE_XMP_TOOLKIT` is always ON when xmpsdk is active. The `XMLValidator` class defined under that guard is therefore always compiled in alongside xmpsdk, so the mitigation is unconditionally present.

---

After exhaustive multi-file analysis of `XMPUtils.hpp` and all related implementation files (`XMPUtils.cpp`, `XMPUtils-FileInfo.cpp`, `ParseRDF.cpp`, `XMPMeta-Parse.cpp`, `ExpatAdapter.cpp`, `xmp.cpp`, `image.cpp`), the findings are:

**Stack overflow (ParseRDF.cpp recursive descent):** The `RDF_NodeElement → RDF_PropertyElementList → RDF_PropertyElement → RDF_ResourcePropertyElement → RDF_NodeElement` mutual recursion has no depth guard inside xmpsdk, but `XMLValidator::check()` (xmp.cpp:689) runs a pre-flight Expat pass with `max_recursion_depth_=1000` before any xmpsdk call. This mitigation is always active whenever xmpsdk is compiled (`EXV_HAVE_XMP_TOOLKIT`). The exploitation path is blocked at the library boundary.

**ClassifyCharacter OOB read (XMPUtils-FileInfo.cpp):** For leading byte `0xFF`, `charSize` is computed as 8 and the code reads 7 continuation bytes without bounds check. However, `ProcessUTF8Portion` (XMPMeta-Parse.cpp) converts every non-valid UTF-8 byte — including `0xFF` — to its UTF-8 Latin-1 replacement sequence *before* Expat stores the value in any XMP node. Consequently, no XMP node value reachable from a crafted image file can contain a `0xFF` leading byte; the OOB path is unreachable from external input.

**DecodeFromBase64 inner-loop OOB (XMPUtils.cpp):** The `inChunk/inStr` decoupling in the final-chunk loop can advance `inStr` past `encodedLen` when leading whitespace causes the main loop to consume the last chunk's data bytes. The `XMP_Assert(inStr < encodedLen)` at line 1627 catches this only in debug builds. In release builds, `encodedStr[inStr]` is read past the buffer. However, all callers in exiv2's XMP processing path supply strings via `std::string::c_str()`, which guarantees a null terminator at `encodedStr[encodedLen]`; `DecodeBase64Char('\0')` throws `XMP_Throw` before any heap corruption occurs. The raw-pointer API (`XMP_StringPtr + XMP_StringLen`) could accept a non-null-terminated buffer, but exiv2 never passes one on any image-parsing code path.

---

`NO_VULN_FOUND`

<!-- AUDIT_PROMPT_VERSION: 1 -->
