# VULN 002 — ctts atom integer overflow → heap-buffer-overflow

## Status
VERIFIED_CRASH (AddressSanitizer heap-buffer-overflow)

## Vulnerability summary

File: `Source/C++/Core/Ap4CttsAtom.cpp`, lines 77-98

```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);
m_Entries.SetItemCount(entry_count);                 // line 79
unsigned char* buffer = new unsigned char[entry_count*8]; // line 80  <-- BUG
AP4_Result result = stream.Read(buffer, entry_count*8);   // line 81
...
for (unsigned i=0; i<entry_count; i++) {             // line 88
    m_Entries[i].m_SampleCount  = AP4_BytesToUInt32BE(&buffer[i*8  ]); // OOB read
    ...
}
```

`entry_count` is `AP4_UI32` (32-bit unsigned). The expression `entry_count * 8` is computed in
the same 32-bit domain. With `entry_count = 0x20000000`:

    0x20000000 * 8 = 0x100000000  →  truncated to 0 (uint32 wrap)

`new unsigned char[0]` returns a valid but zero-length (effectively 1-byte in practice)
allocation. The subsequent `stream.Read(buffer, 0)` succeeds trivially, and then the loop
immediately performs an out-of-bounds read starting at `buffer[0]` through `buffer[7]`.

## Trigger path

    main()
     └─ AP4_File(stream)
         └─ ParseStream()
             └─ AP4_DefaultAtomFactory::CreateAtomFromStream()
                 └─ AP4_CttsAtom::Create()
                     └─ new AP4_CttsAtom(size, version, flags, stream)  ← crash here

## PoC construction

A minimal, structurally valid MP4 is constructed entirely in Python (no C/C++):

    ftyp (20 bytes)
    moov
      mvhd (108 bytes)
      trak
        tkhd (92 bytes)
        mdia
          mdhd (32 bytes)
          hdlr (45 bytes)
          minf
            smhd (16 bytes)
            dinf → dref → url (28 bytes)
            stbl
              stsd (16 bytes)
              stts (16 bytes)
              ctts (16 bytes)  ← malicious: entry_count=0x20000000, no entry data

Total file size: 437 bytes.

The ctts box is only 16 bytes (header 8 + version/flags 4 + entry_count 4). No actual
entry data is present, which is consistent with the overflow — the parser tries to read
`0 * 8 = 0` bytes from the stream (succeeds), then walks into OOB memory in the loop.

## ASAN output (excerpt)

    ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000000f1
    READ of size 1 at 0x5020000000f1 thread T0
      #0 AP4_CttsAtom::AP4_CttsAtom(...)  Ap4CttsAtom.cpp
    0x5020000000f1 is located 0 bytes to the right of 1-byte region
    allocated by: operator new[](unsigned long)  <- new unsigned char[0]

## Fix

Validate `entry_count` against the atom's declared size before allocation:

```cpp
AP4_UI32 max_entries = (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8;
if (entry_count > max_entries) {
    // reject or clamp
    return;
}
```

Alternatively, use checked multiplication:
```cpp
if (entry_count > UINT32_MAX / 8) { return; }
unsigned char* buffer = new unsigned char[(size_t)entry_count * 8];
```

The cast to `size_t` before the multiply also prevents overflow on 64-bit platforms.
