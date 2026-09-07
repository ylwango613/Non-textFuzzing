Now I have the full picture. Let me verify the key arithmetic checks carefully.

**Analysis of `AP4_PsshAtom.cpp` (full file, 266 lines):**

**Group 1 — Lines 79–110, constructor (stream-parsing path)**

- Line 86: `size < AP4_FULL_ATOM_HEADER_SIZE + 20` → ensures `size >= 32` before any subtraction.
- Line 92 guard: `m_KidCount > (size - 32) / 16` — all operands are `AP4_UI32`. With `size` max `0xFFFFFFFF`, floor `(0xFFFFFFFF-32)/16 = 268435453`. Therefore `m_KidCount ≤ 268435453`, and `m_KidCount*16 ≤ 4294967248 < 2^32` — **no overflow**.
- Line 96: `m_Kids.SetDataSize(m_KidCount*16)` — confirmed non-overflowing.
- Line 101: `data_size > AP4_PSSH_MAX_DATA_SIZE` (16 MB cap) — data capped at 16 MB.
- Lines 104–108 — padding: `padding_size = size - computed_size`. For `version==0`, `computed_size = 32 + data_size` (max ~16 MB), so `padding_size` can be huge if `size` is attacker-supplied large. `ReallocateBuffer` uses bare `new` (throws `std::bad_alloc`, not return null), so OOM → unhandled exception → DoS crash only — **no heap-write with wrong size**.
- For `version==1`, `GetComputedSize()` can wraparound if `m_KidCount` is near max AND `data_size` is 16 MB, but reaching that state requires a ~4 GB file.

**Group 2 — Lines 131–138, `GetKid`**

Bounds-checked via `index >= m_KidCount`. Buffer exactly `m_KidCount*16` bytes — safe.

**Group 3 — Lines 206–230, `WriteFields`**

`m_KidCount*16` is the same proven non-overflowing value. Reads from `m_Kids` buffer of exactly that size.

**Group 4 — Lines 235–265, `InspectFields`**

`"kid %d"` with `i` max `268435453` → 13 chars + null, fits in `kid_name[32]`.

**`ReallocateBuffer` review (Ap4DataBuffer.cpp:204–225):**

`new AP4_Byte[size]` — throws on OOM, never returns null. Code never reaches a state where `UseData()` returns a stale undersized pointer while a larger write is attempted.

**Conclusion:** The KID-count guard is mathematically tight (no overflow possible after the check), `data_size` is hard-capped, and the only risk path (large `padding_size`) leads to OOM throw → DoS, not a heap write-past-end.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
