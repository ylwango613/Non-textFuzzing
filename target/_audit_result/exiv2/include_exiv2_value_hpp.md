After fully reading value.hpp (1659 lines), value.cpp, types.cpp, tiffvisitor_int.cpp (IFD reader bounds checking at lines 1246-1328), convert.cpp (charset conversion), and all key callers, my findings across every round of analysis are:

1. **`ValueType<T>::read` ts=0 infinite loop** (value.hpp:1472): Only if `typeSize(typeId())==0`, but `Value::create` always routes unknown typeIds to `DataValue`, never `ValueType<T>`. The TIFF reader also normalises unknown typeSize to 1 before calling `Value::create` (tiffvisitor_int.cpp:1248-1254). Not reachable from a crafted file.

2. **`size()` / `copy()` mismatch (heap overflow)**: All subclasses are consistent — `DataValue`, `StringValueBase`, `ValueType<T>`, `XmpValue`, and `CommentValue` all write exactly `size()` bytes. The `CommentValue::copy()` unicode path calls `convertStringCharset("UCS-2LE","UCS-2BE")` which is a pure byte-swap (verified in convert.cpp `ucs2leToUcs2be` → `swapBytes`): output length == input length. No overflow.

3. **TIFF IFD entry bounds checking**: The reader validates `count < 0x10000000`, checks overflow with `Safe::add` and `count > SIZE_MAX / typeSize`, and truncates `size` to 0 if out of bounds (lines 1267–1318). The `v->read(pData, size, byteOrder())` call always receives a correctly bounded `size`.

4. **`DataBuf::data()` returning nullptr**: Only when the buffer is empty (size 0). Every `copy()` implementation safely handles the empty-value_ case, writing 0 bytes. No null-pointer write.

5. **`value_.at(n)` calls** in `toString(n)`, `toInt64(n)`, etc.: These throw `std::out_of_range`, not UB — not memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
