# VULN 004 — AP4_SaioAtom Bounds-Check Integer Overflow → OOM/Null Deref

## Vulnerability Summary

- **Location**: `Ap4SaioAtom.cpp:110`, function `AP4_SaioAtom::AP4_SaioAtom()`
- **Type**: Integer overflow leading to bounds-check bypass → `std::bad_alloc` / DoS
- **CWE**: CWE-190 (Integer Overflow), CWE-400 (Uncontrolled Resource Consumption)

## Root Cause

The bounds check at line 110:

```cpp
if (remains < entry_count*(m_Version==0?4:8))
```

uses `uint32_t` arithmetic. When `version=0` and `entry_count = 0x40000000`:

```
entry_count * 4 = 0x40000000 * 4 = 0x100000000 -> wraps to 0 (uint32_t overflow)
```

So `remains < 0` is always false (remains is unsigned and 0 is minimum), bypassing the check entirely. The code then calls:

```cpp
m_Entries.SetItemCount(entry_count);  // entry_count = 0x40000000 = ~1 billion
```

which attempts to allocate ~4 GB of memory (`0x40000000 * sizeof(AP4_SI64)` = 4 GB), causing `std::bad_alloc` and a crash (DoS).

## PoC Approach

The generator (`vuln_004_gen.py`) constructs a minimal but structurally valid MP4 file containing a `saio` box with:
- `version = 0` (selects 4-byte offset entries)
- `flags = 0x000000` (bit 0 = 0, so no `aux_info_type`/`aux_info_type_parameter` fields)
- `entry_count = 0x40000000` (triggers the overflow)
- 4 dummy trailing bytes (ensures `remains > 0` at the check point)

The integer overflow:
- `entry_count * 4 = 0x40000000 * 4 = 0x100000000` truncates to `0` in `uint32_t`
- The check `remains < 0` is always false → bypass
- `SetItemCount(0x40000000)` → massive allocation → crash

## Expected Behavior

- **Without fix**: Process crashes with `std::bad_alloc` or OOM signal
- **With ASAN**: May report `ASAN: allocation-size-too-large` or similar, or just terminate
- **With fix**: Use 64-bit arithmetic (`(AP4_UI64)entry_count * (m_Version==0?4:8)`) for the bounds check

## Files

- `vuln_004_gen.py`: Generates `vuln_004.mp4`
- `vuln_004_run.sh`: Runs the PoC and collects output
- `vuln_004.mp4`: Malicious MP4 file (generated at runtime)
- `vuln_004_result.txt`: stdout/stderr from mp42aac
- `asan.log.*`: ASAN output if binary is instrumented
