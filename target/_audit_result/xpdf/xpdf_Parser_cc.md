Now I have the full picture. Let me verify the critical kludge block's object lifetime.

The `BaseStream::BaseStream(Object *dictA)` does `dict = *dictA` — a **shallow** C++ assignment (no destructor on `Object`, no `copy()` increment). The `Object::copy()` at Parser.cc:258 does `dict->incRef()` for Dict types, and then the shallow assignment in BaseStream transfers that refcount slot cleanly. When `obj` goes out of scope without calling `free()`, the refcount is preserved in `BaseStream::dict`, which later calls `dict.free()` in its destructor — correct by design.

The `(GFileOffset)(Guint)obj.getInt()` cast on line 177 converts negative `/Length` values to large positive numbers (~4 GB), but both `FileStream::fillBuf()` and `MemStream::makeSubStream()` handle oversized lengths gracefully: FileStream reads until real EOF (OS-bounded); MemStream clamps via the `newStart + lengthA > start + length` branch. No downstream allocator uses this length for a `malloc` call within Parser.cc itself.

The `shift()` buf1/buf2 pattern is a deliberate move-semantics idiom: `buf1.free()` releases old buf1, `buf1 = buf2` shallow-copies ownership, then buf2 is re-initialized without freeing (since ownership transferred to buf1). Correct.

No direct buffer overflow, OOB read/write, or UAF is present in Parser.cc itself.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
