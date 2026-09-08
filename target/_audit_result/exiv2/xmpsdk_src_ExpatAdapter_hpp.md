I have now fully read and analyzed `ExpatAdapter.hpp`, its implementation `ExpatAdapter.cpp`, the base class `XMLParserAdapter.hpp`, and the calling context in `XMPMeta-Parse.cpp`. I also checked expat's API signature (`XML_Parse` takes `int len`), the type of `XMP_StringLen` (`uint32_t`), and how `XMP_Throw` works (throws `XMP_Error` as a C++ exception).

**Analysis summary (file group: ExpatAdapter.hpp + ExpatAdapter.cpp)**

**ExpatAdapter.hpp (lines 19-21):** `BanAllEntityUsage` defaults to 0, so DOCTYPE/entity expansion is enabled. This is an XML Billion Laughs DoS/resource exhaustion — not a memory corruption issue as defined by the audit scope.

**ExpatAdapter.cpp line 135 (`XML_Parse` call):** `length` is `size_t` but `XML_Parse` takes `int`. If `length > INT_MAX`, expat receives a negative length, which can cause OOB access inside expat. However, `length` originates from `XMP_StringLen` (uint32_t), and a >2GB XMP packet in an image file is not a practical attacker scenario.

**ExpatAdapter.cpp lines 198-201 (`SetQualName`):** If `fullName` is the empty string, `--sepPos` on `size_t(0)` wraps to `SIZE_MAX`, causing an OOB backward memory scan. However, expat (used in namespace mode) never delivers an empty element name per the XML specification, making this unreachable via attacker-controlled input.

**ExpatAdapter.cpp line 357 (`parseStack.pop_back()`):** Called without checking for empty vector. Expat's XML validation guarantees matched start/end tags, keeping the stack balanced. Not triggerable under well-formed or even malformed XML (expat returns an error before calling the handler for unmatched end tags).

**`pendingInput` buffer (XMPMeta-Parse.cpp lines 1140, 1191, 1230, 1251):** All four `memcpy` calls are annotated `// AUDIT: Count is safe.` and are bounded by `kXMLPendingInputMax = 16`. Verified correct.

None of the identified patterns are practically exploitable as memory-safety bugs via a crafted image file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
