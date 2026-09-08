Having thoroughly analyzed the file and its dependencies, here is my assessment:

**File structure**: `NameToCharCode.cc` is a 114-line open-addressing linear-probe hash table that maps glyph name strings to `CharCode` integers.

**Analysis findings:**

1. **Allocation safety**: `gmallocn(size, sizeof(NameToCharCodeEntry))` is protected by overflow/negative checks inside `gmallocn` (`nObjs < 0 || nObjs >= INT_MAX / objSize`).

2. **Linear probe termination**: The expansion guard `if (len >= size / 2)` ensures load factor ≤ 50%, so at least one NULL slot always exists — both `add()` and `lookup()` probe loops always terminate.

3. **Rehash loop**: Copies at most `oldSize` entries into a table of `2*oldSize + 1` slots (all initialized NULL), always safe.

4. **`len` overcounting**: When `add()` updates an existing name (duplicate), `tab[h].name` is non-NULL and matched, so no `copyString` is called, but `++len` still fires. This over-counts `len`, causing premature resizes. It is a logic bug only — it does not allow the table to become completely full, and thus causes no memory safety impact.

5. **`size` integer overflow**: After ~30 doublings (`2*size + 1` with `int size`), `size` could overflow to negative, but `gmallocn`'s `nObjs < 0` check would call `gMemError()` (abort), not cause heap corruption. Requires ~2³⁰ `add()` calls — not realistic via a crafted PDF.

6. **No UAF**: Destructor iterates all `size` slots and frees non-NULL names, then frees `tab`. No dangling pointer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
