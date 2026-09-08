**Batch 1 analysis (lines 1–173 — AddSchemaProps, AddSchemaAliases, AddNodeOffspring):**
- `leafOffset` is always initialized to `iterParent.fullPath.size()`, incremented by 2 for the `"/?"`  prefix and decremented back symmetrically. `std::string::erase(pos)` with `pos == size()` is well-defined (removes nothing). No OOB.
- `currPath += xmpQual->name` then `currPath.erase(leafOffset)`: resets to pre-child state, bounded correctly.

**Batch 2 analysis (lines 210–297 — AdvanceIterPos):**
- `IterPosPair & parent = info.ancestors.back()` (line 231): reference captured, `parent.first`/`parent.second` copied to `info.currPos`/`info.endPos`, then `pop_back()` — reference becomes dangling but is never used again. Safe.
- `info.ancestors.push_back(...)` at lines 260/271: can reallocate `ancestors` vector, but `info.currPos`/`info.endPos` are iterators into *other* vectors (siblings list), not into `ancestors`. No invalidation.
- `info.currPos->qualifiers.clear()` (line 268): called only after ancestor iterators into qualifiers have already been popped and discarded. No use-after-free.

**Batch 3 analysis (lines 300–600 — GetNextXMPNode, constructors):**
- `AddNodeOffspring(info, *info.currPos, xmpNode)` at line 357: modifies `(*info.currPos).qualifiers` and `(*info.currPos).children`. These are sub-vectors of the element pointed to by `info.currPos`, not the parent vector containing `info.currPos`. No reallocation of parent vector, so `info.currPos` stays valid.
- `info.tree.children.push_back(...)` inside the schema loop (line 509): loop uses an index (`schemaNum`), not an iterator; `iterSchema` ref is to `.back()` after push, then `AddSchemaProps`/`AddSchemaAliases` only push to `iterSchema.children`, not to `info.tree.children`. No reallocation of `info.tree.children` while `iterSchema` is held. Safe.

**Batch 4 analysis (lines 600–737 — Next, Skip):**
- Lines 658–659: `*propPath += info.currPos->leafOffset` (pointer advance) and `*pathSize -= info.currPos->leafOffset` (unsigned subtraction). `leafOffset` is constructed to always be ≤ `fullPath.size()` = `*pathSize` (derived directly from parent's `fullPath.size()` plus bounded separator increments). No underflow, no OOB pointer advance.
- `Skip()` line 700 (TraceIterators printf): guarded by `#if TraceIterators` which is `#define TraceIterators 0`. Compiled out in all production builds.

**Overall conclusion:** XMPIterator.cpp operates entirely on the already-parsed XMP `XMP_Node` tree — it does not touch raw file bytes. All container operations use C++ STL with proper size tracking; `leafOffset` is always valid; no iterator invalidation pattern is present; no raw `memcpy`/`malloc` with unsanitized sizes appears. No externally-triggerable memory safety vulnerabilities were found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
