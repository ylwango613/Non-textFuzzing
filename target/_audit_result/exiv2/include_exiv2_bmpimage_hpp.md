All buffer accesses in `bmpimage.cpp` are within the fixed 26-byte stack buffer:
- `getULong(buf+14)` reads indices 14–17 ✓
- `getUShort(buf+18)` reads indices 18–19 via Slice with `.at()` bounds check ✓
- `getUShort(buf+20)` reads indices 20–21 ✓
- `getULong(buf+18)` reads indices 18–21 ✓
- `getULong(buf+22)` reads indices 22–25 ✓

The header file is purely a class declaration. The implementation only reads a fixed-size BMP header into a fixed stack buffer, assigns the result to plain `uint32_t` fields, and throws on any write attempt. No allocations, no recursion, no pointer arithmetic beyond verified-in-bounds offsets.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
