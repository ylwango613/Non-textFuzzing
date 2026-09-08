Having read the entire `xmp.cpp` (1130 lines) in batches and traced all relevant call chains, let me summarize what I found before rendering the final verdict.

**Batch 1 (lines 1–200):** XMLValidator class — depth checked via `element_depth_ > max_recursion_depth_` (off-by-one: allows depth `limit+1`), but `setError` does not call `XML_StopParser`, so expat continues iterating (no C-stack recursion). Error is thrown post-parse, blocking xmpsdk.

**Batch 2 (lines 200–400):** Xmpdatum RAII wrappers — all smart pointers, no raw memory ops.

**Batch 3 (lines 400–600):** `eraseFamily` — iterates vector, collects keys, then erases via fresh `findKey` iterators. Original `pos` invalidated by vector erasure (std::vector guarantees: all iterators at/after erased position are invalidated). Caller at `actions.cpp:1275` does NOT use `pos` after `eraseFamily` returns. No actual dereference of invalid iterator.

**Batch 4 (lines 600–800):** `decode()` — `len > INT_MAX` guard correctly blocks the `static_cast<XMP_StringLen>(len)` truncation path. `propPath.substr(propPath.size() - 8, 8)` at line 743 would throw `std::out_of_range` for short paths, but xmpsdk propPath format always includes the full property path making it ≥ 8 chars in practice; even if triggered, it's `std::terminate` (DoS), not memory corruption.

**Batch 5 (lines 800–1130):** `encode()`, helper functions — all standard library operations, no raw pointer arithmetic.

**xmpsdk/ParseRDF.cpp:** Recursive call chain `RDF_ResourcePropertyElement → RDF_NodeElement → RDF_PropertyElementList → RDF_PropertyElement → RDF_ResourcePropertyElement`. Depth × ~3–4 frames per XML level. For limit=500 (off-by-one allows 501): ≈1500–1700 frames × ~200 bytes = ~300–340 KB — well within standard 8 MB stack. Not exploitable.

**ExpatAdapter.cpp:** DOM built iteratively via `parseStack` (std::vector), no C-stack recursion during XML ingestion.

No out-of-bounds memory read/write, no integer overflow to allocator underallocation, no heap overflow, no use-after-free with dereference, and no practical stack overflow path exists in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
