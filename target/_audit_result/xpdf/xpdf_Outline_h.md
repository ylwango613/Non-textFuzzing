**Analysis Summary for Outline.h / Outline.cc (183 lines total)**

**Group 1 — Outline constructor / destructor (lines 22–42):**
- Looks up `First`/`Last` refs from the outline dict, delegates to `readItemList`. Proper `free()` on both objects. No OOB, no size arithmetic. Clean.

**Group 2 — OutlineItem constructor (lines 46–85):**
- Reads `Title` (GString → TextString), `Dest`/`A` (LinkAction), `First`/`Last`/`Next` (refs), `Count` (int). All are looked up through the dict API; no raw pointer arithmetic, no size multiplications, no `malloc` in this scope. Clean.

**Group 3 — OutlineItem destructor (lines 87–99):**
- Calls `close()` (which does `deleteGList`), then `delete title`, `delete action`, `itemRef.free()`, etc. Ordering is correct; no double-free path visible. Clean.

**Group 4 — readItemList traversal loop (lines 101–161):**
- Pointer `p` starts as `firstItemRef`; after each appended item becomes `&item->nextRef`. Because items are stored in the `GList` (heap), `&item->nextRef` remains valid across GList reallocation (GList stores pointers-to-objects, not inline). No dangling pointer.
- Cycle detection covers two cases: (a) ancestor chain walk, (b) O(n) sibling scan. If a match is found, the freshly created `item` is `delete`d and the loop breaks — no memory leak, no UAF.
- The `while (p)` sentinel is always true (pointer to an Object member); all exits are explicit `break`. Bounded by the sibling duplicate check — any repeated ref terminates the loop. No infinite loop memory exhaustion beyond what XRef limits.
- No integer overflow: no size arithmetic; only reference-number comparisons (`int` vs `int`).

**Group 5 — open / close / getters (lines 163–182):**
Trivial delegation. Clean.

**Verdict:** No exploitable memory-safety bug is present in Outline.h / Outline.cc. The cycle-detection logic is sound, memory ownership is clear, and no unchecked attacker-controlled integer is used in a size or index calculation within this file. Vulnerabilities, if any, would reside in called code (TextString, LinkAction::parseDest/parseAction, XRef::fetch) outside the scope of this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
