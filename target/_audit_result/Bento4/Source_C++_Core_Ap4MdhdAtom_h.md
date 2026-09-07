Now I have enough context to conclude the analysis. Let me review the complete picture:

**Group 1 — `Create()` size check (Ap4MdhdAtom.cpp:45–53):**
The only size guard is `size < AP4_FULL_ATOM_HEADER_SIZE` (i.e., < 12). For version=1, the constructor reads 8+8+4+8+2 = 30 bytes of payload, but no minimum-size check covers this. This causes reads past the atom boundary in the stream — a logic/data-contamination bug, not a memory-safety bug. No allocation depends on `size`; stream reads cannot overflow a fixed buffer.

**Group 2 — Private constructor field reads (Ap4MdhdAtom.cpp:80–115):**
All reads are into fixed-size primitive members (`AP4_UI32`, `AP4_UI64`) or a 2-byte stack array. No heap allocation is driven by stream data here. `m_CreationTime`/`m_ModificationTime`/`m_TimeScale`/`m_Duration` left uninitialized in the initializer list — if stream fails silently, UB in value, but no memory corruption possible.

**Group 3 — Language parsing (Ap4MdhdAtom.cpp:104–114):**
`lang[2]` is a stack array. Values are masked to 5 bits via `&0x1F`, then added to `0x60` to produce printable chars. Resulting values fit in signed `char` (0x60–0x7F). `m_Language.Assign(lang_str, 3)` always passes hardcoded `size=3`.

**Group 4 — `AP4_String::Assign(s, 3)` (Ap4String.cpp:161–168):**
`new char[3+1]` — size is hardcoded, not attacker-controlled. `AP4_CopyMemory(m_Chars, s, 3)` copies from a fully-initialized 3-char array. No overflow.

**Group 5 — `WriteFields` language indexing (Ap4MdhdAtom.cpp:146–148):**
`m_Language[0..2]` via unchecked `operator[]`. However, every code path in both constructors calls `Assign(…, 3)`, ensuring `m_Length = 3` and `m_Chars` has 4 bytes allocated. Indices 0–2 are always in bounds. `WriteFields` is also not in the mp42aac read-only parsing path.

**Group 6 — `GetDurationMs()` (Ap4MdhdAtom.cpp:161–165):**
Delegates to `AP4_DurationMsFromUnits` which explicitly guards `units_per_second == 0`.

**Conclusion:** No heap allocation is sized from attacker-controlled data, all stack arrays are fixed-size and correctly bounded, and the unchecked `operator[]` in WriteFields cannot be reached out-of-bounds from any parsing code path. There are no exploitable memory-safety vulnerabilities in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
