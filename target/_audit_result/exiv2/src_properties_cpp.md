I've completed a full multi-pass audit of `properties.cpp`:

- **Lines 1–4938**: ~4850 lines of static `constexpr`/`const XmpPropertyInfo` / `XmpNsInfo` data tables — no executable code.
- **Lines 4939–5387**: All runtime logic — namespace registry management, key parsing, property lookup, print helpers.

**Key findings for each code section:**

1. **`registerNsUnlocked` (4976–5013)**: Two `std::strcpy` calls at 5006/5009 are each preceded by a correctly-sized `new char[str.size() + 1]`, so no overflow. The guard `if (ns.empty()) return;` at 4977 protects `ns2.back()` at 4980. Steps 2+3 can only remove different keys from the registry; there is no double-free path.

2. **`prefixUnlocked` (5056–5068)**: `ns2.back()` at 5058 has no empty-string guard (unlike `registerNsUnlocked`). However, the only callers are `xmp.cpp:704` and `xmp.cpp:1106` where `schemaNs` comes from `SXMPIterator::Next`. The XMP SDK's `AddChildNode` (ParseRDF.cpp:370-372) throws `kXMPErr_BadRDF` for any empty namespace URI before a schema node with empty name could ever be created — so this code path is unreachable from a crafted image file.

3. **`unregisterAllNsNoLock` (5042–5048)**: Uses the `auto kill = i++` idiom to avoid iterator invalidation; `kill->first` is passed by value to inner call before the map entry is erased. Safe.

4. **`propertyInfoUnlocked` (5121–5145)**: Nested-path handling using `find_last_of`/`find_if`/`substr` — all within bounds. Empty result simply matches no property name.

5. **`decomposeKeyUnlocked` (5341–5363)**: `npos + 1` wraps to 0 (re-scans from start) and triggers the npos check; all error paths throw before any invalid indexing.

6. **`operator<<` for `XmpPropertyInfo` (5369–5384)**: Only called from the loop `for (int i = 0; pl[i].name_; ++i)`, which stops before the null-sentinel entry — so `desc_` is never null.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
