# VULN 005 – AP4_TfraAtom: No bounds check on entry_count → heap OOB / bad_alloc

## Vulnerability Summary

**Component**: Bento4 / `AP4_TfraAtom`  
**Function**: `AP4_TfraAtom::AP4_TfraAtom()` (constructor)  
**File**: Ap4TfraAtom.cpp  
**CWE**: CWE-789 (Uncontrolled Memory Allocation) / CWE-400 (Uncontrolled Resource Consumption)

## Root Cause

In the `AP4_TfraAtom` constructor, the `number_of_entry` field (entry_count) is read directly from the MP4 file stream without any upper-bound validation. The value is passed directly to `SetItemCount()` on an `AP4_Array`, which attempts to allocate memory for `entry_count` elements.

When `entry_count` is set to a very large value (e.g., `0x20000000` = 536,870,912), the resulting allocation (`entry_count * sizeof(AP4_TfraAtom::Entry)`) overflows available memory, causing `std::bad_alloc` and a DoS crash.

## Trigger Path

```
mp42aac input.mp4
  → AP4_AtomFactory::CreateAtomFromStream()
    → AP4_TfraAtom::Create(size, stream)
      → new AP4_TfraAtom(size, version, flags, stream)
        → m_Entries.SetItemCount(number_of_entry)  ← no bounds check
          → std::bad_alloc (OOM crash)
```

## PoC Construction

The crafted MP4 file structure:
- `ftyp` box (iso5 brand)
- `moov` box with minimal valid track (sound track)
- `mfra` box containing:
  - `tfra` (Track Fragment Random Access) full-box:
    - version = 0, flags = 0
    - track_ID = 1
    - length_size fields = 0 (1 byte each for traf/trun/sample numbers)
    - **entry_count = 0x20000000** ← trigger value
    - 1 fake entry (to pass initial parse)
  - `mfro` box with correct mfra size

## Expected Behavior

**With ASAN build**:  
`std::bad_alloc` exception thrown from `AP4_Array::SetItemCount()`, resulting in process termination (DoS).

**Without ASAN**:  
OOM kill or `std::terminate()` depending on system memory state.

## Impact

- **Severity**: Medium (Denial of Service)
- **Attack vector**: Malicious MP4 file
- **Affected versions**: Bento4 (confirmed on build at `/data/ylwang/non-textfuzz/target/Bento4/`)
- Any parser of MP4 files using Bento4's `AP4_TfraAtom` is vulnerable

## Fix Recommendation

Add an upper-bound check before calling `SetItemCount`:

```cpp
if (number_of_entry > AP4_TFRA_MAX_ENTRY_COUNT) {
    return; // or return error
}
m_Entries.SetItemCount(number_of_entry);
```

Where `AP4_TFRA_MAX_ENTRY_COUNT` is a reasonable limit (e.g., 1,000,000).
