Now I have a complete picture of the file and its related class hierarchy. Let me systematically verify the key safety properties:

**Group 1 (lines 43–76): `AP4_CONFIG_NO_RTTI` branch — custom RTTI macros**

- `AP4_DYNAMIC_CAST`: null-checks `_object` before calling `DynamicCast`; uses `reinterpret_cast<_class*>` on the returned `void*`. If `DynamicCast` returns `NULL`, `reinterpret_cast<T*>(NULL)` stays `NULL`. No buffer involvement.
- `AP4_IMPLEMENT_DYNAMIC_CAST`: `DynamicCast` compares the anchor by address (unique static `int` per class). Returns `static_cast<_class*>(this)` on match, `NULL` otherwise. No external input involved.
- `AP4_IMPLEMENT_DYNAMIC_CAST_D`: chains to superclass via qualified (non-virtual) call. If no match, returns `NULL`. No external input.
- `AP4_IMPLEMENT_DYNAMIC_CAST_D2`: For multiple inheritance (e.g., `AP4_MpegAudioSampleDescription : AP4_MpegSampleDescription, AP4_AudioSampleDescription`). Calls `_superclass::DynamicCast` and `_mixin::DynamicCast` with qualified names — virtual dispatch is suppressed, so `this` is correctly adjusted for the mixin subobject by the compiler. `static_cast<_mixin*>(this)` inside the mixin's `DynamicCast` returns the right subobject pointer. The `void*` propagated back and then `reinterpret_cast<_class*>`-ed correctly points to the subobject. No external file data touches the RTTI logic.

**Group 2 (lines 77–86): RTTI-available branch**

Simply maps to `dynamic_cast` and empty macros. No custom logic at all.

**External-input reachability check:**

None of the anchor comparison values (`&_class::_class_##_class`) or the RTTI dispatch paths are derived from MP4 file bytes. The RTTI mechanism operates purely on compile-time-fixed addresses. There is no size arithmetic, no allocation, no buffer write, and no index computed from file data in this file. The `AP4_DYNAMIC_CAST` null-guards `_object` so a NULL object never reaches `DynamicCast`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
