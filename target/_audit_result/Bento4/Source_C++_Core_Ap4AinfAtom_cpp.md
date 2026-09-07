All types confirmed (`AP4_Size` = `AP4_UI32`). The analysis is complete.

**Summary of findings in `Ap4AinfAtom.cpp`:**

- `size` is bounded to `[17, 16777215]` (lines 78) by `AP4_AINF_MAX_OTHER_SIZE = 16MB` before any arithmetic.
- `payload_size = size - 16` is within `[1, 16777199]` — no underflow, no overflow.
- `payload.SetDataSize(payload_size+1)` allocates at most 16777200 bytes — no 32-bit overflow.
- `payload.UseData()[payload_size] = 0` writes within bounds (buffer size = `payload_size+1`).
- `stream.Read(payload.UseData(), payload_size)` reads into buffer of `payload_size+1` — safe.
- `m_APID.GetLength()` ≤ `payload_size` (forced null at index `payload_size`), so `GetLength()+1` ≤ `payload_size+1` — no overflow in the comparison on line 86.
- `other_boxes_size = payload_size - m_APID.GetLength() - 1`: the `if` condition on line 86 guarantees `other_boxes_size > 0`, no underflow.
- `AP4_CopyMemory` reads `other_boxes_size < payload_size < payload_size+1` bytes from the payload buffer — no OOB. The destination is sized to exactly `other_boxes_size` — no OOB write.

The logic bug (wrong source offset: copies from start of payload instead of after the APID string) does not cross buffer boundaries.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
