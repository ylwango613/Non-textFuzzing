After thorough analysis of both `pngchunk_int.hpp` and `pngchunk_int.cpp` in full, including all callers and DataBuf bounds semantics, here is the complete picture:

- **`decodeIHDRChunk`**: `DataBuf::read_uint32` throws on OOB; pngimage.cpp additionally guards with `chunkData.size() >= 8`. Safe.
- **`parseTXTChunk` (zTXt)**: `enforce(data.size() >= keysize + 2)` before all accesses; `uint32_t` truncation only for chunks > 4 GB. Safe.
- **`parseTXTChunk` (iTXt)**: `string_from_unterminated(nullptr, 0)` is safe (returns `{}` on `data_length==0`). The `static_cast<long>` / implicit `long→unsigned int` to `zlibUncompress` requires > 4 GB data. Safe.
- **`readRawProfile`**: The `if (sp >= eot) { return info; }` guard on line 491 catches the `text.size()==2` edge case where `sp == eot` initially. All loops guard with `if (sp == eot) { return; }` after each increment. The `enforce(length <= (eot-sp)/2)` before `info.alloc(length)` prevents size-overflow exploitation; `info.size() != length` catches any allocation failure. `unhex` accesses are bounded to indices 48–102 (within array size 103). Safe.
- **`zlibUncompress`**: DoS cap at 131072 bytes; `uLongf` is 64-bit so `compressedTextSize * 2` doesn't overflow. Safe.
- **`makeUtf8TxtChunk`**: `text.data()` instead of sized string constructor is an encode-path API issue, not triggerable via crafted input file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
