Now I have all the context needed for the analysis. Let me trace the complete vulnerability:

**Analysis of `Ap4SdpAtom.cpp` constructor (line 54–66):**

```cpp
AP4_SdpAtom::AP4_SdpAtom(AP4_UI32 size, AP4_ByteStream& stream)
{
    AP4_Size str_size = size - AP4_ATOM_HEADER_SIZE;   // AP4_Size = AP4_UI32
    if (str_size > 0) {
        char* str = new char[str_size+1];
        stream.Read(str, str_size);
        str[str_size] = '\0';
        ...
    }
}
```

`AP4_ATOM_HEADER_SIZE` = 8. `AP4_Size` = `AP4_UI32`.

**Underflow path via `size_32 = 0` from file:**

In `Ap4AtomFactory.cpp:194–199`, when the file's 32-bit box size field is `0`, the outer factory sets the 64-bit `size = stream_size - start` but leaves `size_32 = 0` unchanged. It then passes `size_32 = 0` to the inner `CreateAtomFromStream` (line 221), which routes to:

```cpp
case AP4_ATOM_TYPE_SDP_:
    atom = AP4_SdpAtom::Create(size_32, stream);   // size_32 = 0!
```

In the constructor: `str_size = 0 - 8 = 0xFFFFFFF8` (unsigned underflow). `str_size > 0` is true → `new char[0xFFFFFFF9]` → `std::bad_alloc` → unhandled exception → crash.

There is **no lower-bound check** on `size` before passing it to `AP4_SdpAtom::Create`. The only factory guard is `atom_is_large = (size_32 == 1)`, which is false for `size_32 = 0`.

## VULN: AP4_SdpAtom constructor integer underflow leading to excessive allocation (DoS)
- **漏洞类别**: memory-safety
- **函数**: AP4_SdpAtom::AP4_SdpAtom(AP4_UI32 size, AP4_ByteStream& stream)
- **行号**: 54-66 (Ap4SdpAtom.cpp)
- **CWE**: CWE-191 (Integer Underflow / Wrap or Wraparound)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() [outer, Ap4AtomFactory.cpp:139] → reads size_32=0 from file, sets size=stream_size-start but leaves size_32=0 unchanged → AP4_AtomFactory::CreateAtomFromStream() [inner, Ap4AtomFactory.cpp:257] → case AP4_ATOM_TYPE_SDP_: AP4_SdpAtom::Create(size_32=0, stream) → AP4_SdpAtom::AP4_SdpAtom(size=0, stream) → str_size = 0 - 8 = 0xFFFFFFF8 → new char[0xFFFFFFF9]
- **描述**: `AP4_Size` は `AP4_UI32`（符号なし32ビット）。MP4ファイルの `sdp_` box の32ビットサイズフィールドが 0（「ファイル末尾まで」を意味するISO 14496-12仕様値）の場合、外側ファクトリは64ビット `size` を実際のストリームサイズに更新するが `size_32` は 0 のまま内側ファクトリに渡す。コンストラクタ内で `AP4_Size str_size = size - AP4_ATOM_HEADER_SIZE` = `0 - 8` = `0xFFFFFFF8`（符号なし整数アンダーフロー）。`str_size > 0` が真になり `new char[0xFFFFFFF9]`（約4GB）を要求する。標準C++では `std::bad_alloc` 例外が発生し、呼び出しスタック上でキャッチされないためプロセスが `std::terminate()` で終了する。
- **触発条件**: MP4ファイル内に type=`sdp_` で32ビットサイズフィールドを 0x00000000 に設定した box を配置する（box は moov/trak/mdia/minf/hnti など hint track 構造内に埋め込み可能）。ファイルとして有効な8バイトヘッダ（`\x00\x00\x00\x00sdp_`）を持つだけで十分。
- **安全影響**: プロセス強制終了（DoS）。`mp42aac` をバッチ処理パイプラインやサーバサイドメディア処理に組み込んでいる場合、攻撃者は任意のタイミングでサービスをクラッシュさせることができる。

<!-- AUDIT_PROMPT_VERSION: 1 -->
