After reading all relevant code (WXMPIterator.cpp, XMPIterator.cpp, XMPIterator.hpp, ParseRDF.cpp, XMPCore_Impl.hpp, ExpatAdapter.cpp, XMPMeta-Parse.cpp, xmp.cpp), I'll now do a final verification pass on the key candidate issues identified.

**Group 1 — WXMPIterator.cpp direct logic (lines 1-188)**
- Thin wrapper: null-checks inputs, delegates to XMPIterator, catches exceptions.
- `WXMPIterator_DecrementRefCount_1` (lines 95-107): The `XMP_Assert(thiz->clientRefs > 0)` is a no-op in release builds. A double-decrement causes UAF + double-free, but this requires the *caller* to decrement twice — not triggerable by crafted image content.
- `XMP_EXIT_WRAPPER_KEEP_LOCK(found)` (line 151): Holds the XMP mutex across `Next()` calls by design. Safe within exiv2's usage (Skip is never called between Next calls in xmp.cpp).

**Group 2 — XMPIterator.cpp iterator state management**
- `AdvanceIterPos()`: The critical sequence `currPos = parent.first; endPos = parent.second; ancestors.pop_back()` — values are copied *before* `pop_back()` invalidates the reference. No UAF.
- `qualifiers.clear()`/`children.clear()` after restoring currPos/endPos from ancestors — cleared vectors are no longer referenced by live iterators at that moment. No iterator invalidation.
- `ancestors.push_back()` possible vector reallocation: currPos/endPos point into IterNode member vectors (not into `info.ancestors`), so reallocation of `ancestors` doesn't invalidate them. Safe.

**Group 3 — ParseRDF.cpp recursive descent**
- `RDF_NodeElement → RDF_PropertyElementList → RDF_PropertyElement → RDF_ResourcePropertyElement → RDF_NodeElement` — unbounded mutual recursion, NO depth check inside xmpsdk.
- **Mitigation already in place**: `xmp.cpp` runs `XMLValidator::check(xmpPacket.data(), len, dp)` with `max_recursion_depth_ = 1000` (set at `ImageFactory::open`, line 890) *before* ever calling `SXMPMeta meta(...)`. The comment in xmp.cpp line 37 explicitly acknowledges: *"it is easy to trigger a stack overflow in xmpsdk with a deeply nested tree."* The guard fires before xmpsdk is reached. This is a known, already-mitigated issue.

**Group 4 — PickBestRoot recursion**
- Also recursive over the XML tree, bounded by the same XMLValidator depth limit. Mitigated.

**Group 5 — leafOffset arithmetic in Next() (XMPIterator.cpp lines 657-659)**
- `leafOffset <= fullPath.size()` invariant is maintained by all call sites. `*pathSize -= leafOffset` cannot underflow. Safe.

No externally triggerable, unmitigated memory safety vulnerabilities were found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
