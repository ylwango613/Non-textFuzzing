I have now completed a thorough multi-pass audit of the complete call chain:

**Files read in full:**
- `xmp_exiv2.hpp` (438 lines) — target header
- `src/xmp.cpp` (1130 lines) — full implementation including `XMLValidator`, `decode()`, `encode()`, `eraseFamily()`
- `xmpsdk/src/ExpatAdapter.cpp` (507 lines) — expat bridge
- `xmpsdk/src/ParseRDF.cpp` (1296 lines) — recursive RDF descent parser
- `xmpsdk/src/XMPMeta-Parse.cpp` (1306 lines) — `ParseFromBuffer`, `PickBestRoot`, `ProcessUTF8Portion`, `TouchUpDataModel`
- `xmpsdk/src/XMPUtils.cpp` (selected sections) — snprintf-based conversions
- `src/jpgimage.cpp` — how JPEG decode calls `XmpParser::decode`

**Key observations:**

1. **XMLValidator pre-validation** (`xmp.cpp:67-186`): Runs its own libexpat instance before xmpsdk. Catches deeply nested XML (depth > `max_recursion_depth_` = 1000, ImageFactory sets this at line 890 of image.cpp), malformed XML, and DOCTYPE. Throws `XMP_Error` caught in `decode()` before `SXMPMeta::ParseFromBuffer` runs.

2. **Off-by-one in `startElement`** (`xmp.cpp:123-128`): check fires at depth `> max` instead of `>= max`, so depth of 1001 is allowed. Error IS set and thrown after XML_Parse returns — xmpsdk still never processes it. Not exploitable.

3. **ParseRDF recursive descent** (ParseRDF.cpp): RDF_NodeElement↔RDF_PropertyElement↔RDF_ResourcePropertyElement mutual recursion is bounded by the XML tree depth (≤ 1001 per XMLValidator). ~5000 frames × ~200 bytes = ~1 MB stack usage, well within the 8 MB Linux default.

4. **`eraseFamily` / `erase(end())`** (`xmp.cpp:494-515`): `keys` vector is built from elements that exist in `xmpMetadata_`; each unique key `k` is present in the vector exactly as many times as it appears in metadata. The `findKey(k)` always succeeds. No `erase(end())` UB.

5. **`propPath.substr(propPath.size() - 8, 8)`** (`xmp.cpp:743`): LangAlt qualifier paths are always ≥ 10 chars (minimum form "a:b[1]/c:d"), so `size() - 8` never wraps. No `std::out_of_range` reachable.

6. **`prefix.pop_back()` without empty check** (`xmp.cpp:708`): Follows successful `GetNamespacePrefix()` which always fills a "prefix:" string — xmpsdk guarantees non-empty.

7. **`XMPUtils::ConvertFromInt` snprintf** (XMPUtils.cpp:942): `snprintf` is size-bounded by the allocated buffer; the `XMP_Enforce` check after the fact validates no truncation. Not a real overflow.

8. **`PickBestRoot` recursion** (XMPMeta-Parse.cpp:110-137): Unbounded depth limit BUT bounded in practice by the already-depth-limited XML tree from XMLValidator.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
