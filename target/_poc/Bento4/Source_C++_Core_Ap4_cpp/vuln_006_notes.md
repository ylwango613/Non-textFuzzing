# VULN 006 — AP4_TfraAtom Unchecked entry_count → Unbounded SetItemCount

## Vulnerability

**Location**: `Ap4TfraAtom.cpp:88`  
**Function**: `AP4_TfraAtom::AP4_TfraAtom()`  
**CWE**: CWE-789 (Uncontrolled Memory Allocation)

The constructor reads `entry_count` directly from the MP4 file (a user-controlled uint32_t) and passes it without any bounds check to `m_Entries.SetItemCount(entry_count)`. With `entry_count = 0x10000000` (268 million entries), the runtime attempts to allocate roughly 268M × sizeof(AP4_TfraAtom::Entry) bytes of heap memory, which far exceeds available RAM and triggers `std::bad_alloc`, terminating the process.

## PoC Approach

The generator (`vuln_006_gen.py`) builds a minimal but structurally coherent MP4:

1. **ftyp** box — satisfies brand checks performed before atom parsing.
2. **moov** box — contains a minimal `mvhd`; ensures the file looks like a real MP4.
3. **mfra** box — Movie Fragment Random Access box, normally at end-of-file.
   - **tfra** box — version=0, flags=0, track_id=1, lengths_byte=0x00,  
     **entry_count=0x10000000** (the malicious value), zero entry bytes.
   - **mfro** box — records mfra size (optional but present for realism).

No actual entry data is written after `entry_count`; the crash occurs during `SetItemCount` before the parser tries to read entries.

## Expected Behavior

- `mp42aac` calls `AP4_TfraAtom::AP4_TfraAtom()` when it encounters the tfra box.
- `SetItemCount(0x10000000)` requests ~3+ GB of heap.
- Heap allocation fails → `std::bad_alloc` is thrown and uncaught → process aborts.
- Output: `terminate called after throwing an instance of 'std::bad_alloc'` and/or ASAN `heap-allocation-failure` error.

## Impact

Denial of Service (DoS) — a single crafted file can crash the mp42aac tool and any application that uses the Bento4 library to parse MP4 files containing mfra/tfra boxes.
