Now I have enough context for a complete analysis. Let me work through each potential vulnerability class systematically:

**Analysis: `Ap4StszAtom.cpp`**

**Group 1 — Lines 44-53 (Create):** Checks `size < AP4_FULL_ATOM_HEADER_SIZE` (= 12), so `size >= 12` when entering the constructor. Underflow in `size - 8` is impossible.

**Group 2 — Lines 68-98 (constructor / entry parsing):**

- **Overflow check (line 78):** `if (m_SampleCount > (size-8)/4)` — the correct check should be `(size-20)/4` because the atom header overhead is 8 (basic) + 4 (version+flags) + 4 (SampleSize) + 4 (SampleCount) = 20 bytes. Using `size-8` instead of `size-20` allows up to 3 extra entries beyond atom boundary. **However**, the allocation at line 86 (`new unsigned char[sample_count*4]`) and the read at line 87 (`stream.Read(buffer, sample_count*4)`) are both sized identically to `sample_count*4`, so there is no buffer overflow — just a possible stream-over-read that is caught by the error check.

- **Integer overflow in `sample_count*4` (line 86):** `sample_count` ≤ `(size-8)/4`. With max `size = 0xFFFFFFFF`: max `sample_count = 0x3FFFFFFD`, and `0x3FFFFFFD * 4 = 0xFFFFFFF4` — stays within 32-bit range, no overflow.

- **`EnsureCapacity` overflow (line 85 → Ap4Array.h):** `::operator new(count * sizeof(T))` where `sizeof(AP4_UI32) = 4` and `count = sample_count`. On 64-bit platforms the multiplication is widened to `size_t` — no truncation. Same constraint as above, no 32-bit overflow.

- **SetItemCount return value ignored (line 85):** If `::operator new` returns NULL (non-standard; standard C++ throws `std::bad_alloc`), `m_Items` stays NULL but the loop at line 94 still dereferences it. On Linux/POSIX with standard allocator, `operator new` throws, not returns NULL — not a reliable path. Code has a defensive NULL check inside EnsureCapacity which is dead on standard platforms.

**Group 3 — Lines 141-156 (GetSampleSize):** Bounds check is `sample > m_SampleCount || sample == 0`. After successful parsing, `m_Entries.ItemCount() == m_SampleCount`, so `m_Entries[sample-1]` with `sample` in `[1, m_SampleCount]` is always in-bounds. `AP4_Array::operator[]` has no bounds check but all call-sites are guarded.

**Group 4 — Lines 94-96 (fill loop):** `buffer[i*4]` for `i` in `[0, sample_count-1]` — buffer is `sample_count*4` bytes. Max access: `buffer[sample_count*4-1]`. In-bounds. `AP4_BytesToUInt32BE` reads exactly 4 bytes.

**Conclusion:** No exploitable memory safety vulnerability was found. The overflow check is incorrect (off by 3 entries) but causes only logic/stream errors rather than memory corruption, since allocation and read sizes are always equal. Integer overflow in `sample_count*4` is provably impossible given the guard. The unchecked `SetItemCount` return is dangerous only on platforms where `operator new` returns NULL rather than throwing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
