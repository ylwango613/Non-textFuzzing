# VULN 006 – AP4_StcoAtom Unsigned-Integer Underflow → OOM DoS

## Affected code

**File**: `Bento4/Source/C++/Core/Ap4StcoAtom.cpp`  
**Constructor**: `AP4_StcoAtom::AP4_StcoAtom(AP4_UI32 size, AP4_UI08 version, AP4_UI32 flags, AP4_ByteStream& stream)`  
**Lines 77–81**:

```cpp
stream.ReadUI32(m_EntryCount);
if (m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4) {   // line 78
    m_EntryCount = (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4;
}
m_Entries = new AP4_UI32[m_EntryCount];   // line 81 – crash target
```

## Root cause

`size`, `AP4_FULL_ATOM_HEADER_SIZE` (= 12), and `4` are all `AP4_UI32`.  
When `size = 14`:

```
14 - 12 - 4  →  14 - 16  →  0xFFFFFFFE  (unsigned 32-bit wraparound)
cap = 0xFFFFFFFE / 4 = 0x3FFFFFFF
```

Any `entry_count` ≤ 0x3FFFFFFF bypasses the cap check.  
With `entry_count = 0x10000000` (268 435 456):

```
new AP4_UI32[0x10000000]  →  4 × 268 MB ≈ 1 GiB
```

This triggers `std::bad_alloc` / abort — a Denial of Service.

## Trigger path

```
mp42aac input.mp4
  └─ AP4_AtomFactory::CreateAtomFromStream()
       └─ AP4_StcoAtom::Create(size_32=14, stream)  [raw file stream, no substream]
            └─ new AP4_StcoAtom(14, 0, 0, stream)   ← underflow + OOM here
```

Key observation: `AP4_AtomFactory` passes the **raw file stream** (no per-atom
bounded substream) to `AP4_StcoAtom::Create()`.  Therefore `ReadUI32(m_EntryCount)`
reads 4 consecutive bytes from the file regardless of the declared box size.

## Exploit construction

A 14-byte `stco` box is placed inside `stbl`.  Its layout:

| offset | bytes      | meaning                               |
|--------|------------|---------------------------------------|
| 0–3    | 00 00 00 0E | declared size = 14                   |
| 4–7    | 73 74 63 6F | type = 'stco'                         |
| 8      | 00          | version = 0                           |
| 9–11   | 00 00 00    | flags = 0                             |
| 12–13  | 10 00       | high 2 bytes of entry_count           |
| 14–15  | 00 00       | low 2 bytes (stbl padding, after box) |

`ReadUI32` reads bytes 12–15 → `entry_count = 0x10000000`.

The `stbl` parent is declared large enough so the `bytes_available` check
(`14 ≤ 16`) passes before `Create()` is invoked.

## PoC files

| File              | Purpose                        |
|-------------------|--------------------------------|
| `vuln_006_gen.py` | Generates `vuln_006.mp4`       |
| `vuln_006_run.sh` | Runs mp42aac and records exit  |
| `vuln_006.mp4`    | Crafted MP4 triggering the bug |
