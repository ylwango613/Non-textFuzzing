After completing a thorough multi-pass analysis of `XMPCore_Impl.hpp` and all related files (`ExpatAdapter.cpp`, `ParseRDF.cpp`, `XMPMeta-Parse.cpp`, `XMPCore_Impl.cpp`, `XMPUtils.cpp`, `XMPMeta-Serialize.cpp`, `XMPIterator.cpp`), here is what I found and verified:

**Group 1 — XMPCore_Impl.hpp itself:** Defines typedefs, macros, globals, `XMP_Node`/`XMP_AutoNode`/`XMP_AutoMutex` classes, and function declarations. `XMP_Assert` is a no-op in release builds, but critical safety checks use `XMP_Enforce` (always throws) rather than assertions. The `RemoveChildren`/`RemoveQualifiers` functions correctly null-check before deleting. No direct memory safety defect in this file.

**Group 2 — ExpatAdapter.cpp:** Expat callbacks build an XML tree. `parseStack` is always initialized with the root node; `StartElementHandler`/`EndElementHandler` are balanced by the XML parser. No OOB.

**Group 3 — ParseRDF.cpp (lines 168–1296):** The RDF descent (`RDF_RDF → RDF_NodeElementList → RDF_NodeElement → RDF_PropertyElementList → RDF_PropertyElement → RDF_ResourcePropertyElement → back`) has **no depth limit in the xmpsdk code itself**. This is the historically known stack-overflow CVE pattern. However, checked against **xmp.cpp lines 663–689**: every image-file XMP decode path (JPEG, TIFF, PNG, WEBP, BMFF, RAF, etc.) goes through `XmpParser::decode()`, which calls `XMLValidator::check(xmpPacket.data(), len, dp)` **before** creating `SXMPMeta`. The validator enforces `element_depth_ <= max_recursion_depth_` (default 1000, set from `ImageFactory::open` with `ImageCtorParams(false,1000)`). Stack budget: ≈4 frames × 1001 levels × ~150 bytes ≈ 600 KB, well within the 8 MB default stack.

**Group 4 — XMPMeta-Parse.cpp `ParseFromBuffer`:** Three `memcpy` calls into `pendingInput[kXMLPendingInputMax=16]` are all guarded by size arithmetic ensuring `count ≤ 16`. The UTF-8 replacement table indexing `kReplaceLatin1[*spanEnd - 0x80]` is safe for the `0x80–0xFF` unsigned range (0–127 index into a 128-entry table).

**Group 5 — XMPCore_Impl.cpp `FindIndexedItem`:** The `XMP_Index` (int32_t) overflow check `if (index < 0) XMP_Throw(...)` is present, but this function is only in the XPath expression processing path, not in image-file RDF parsing.

**Group 6 — `PickBestRoot` / `CompareAliasedSubtrees`:** Both recursive on the already-built XML/XMP node tree, which is bounded to ≤1001 depth by the validator. No unbounded recursion.

All image-format parsers confirmed to route through `XmpParser::decode()` with the depth guard:
- `jpgimage.cpp:209`, `pngchunk_int.cpp:279/299`, `tiffvisitor_int.cpp:293`, `webpimage.cpp:676`, `bmffimage.cpp:543/647`, `epsimage.cpp:1061`, `psdimage.cpp:253`, `xmpsidecar.cpp:72`, `image.cpp:622`, `rafimage.cpp:349`, etc.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
