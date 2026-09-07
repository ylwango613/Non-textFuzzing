# VULN 001 – ReadNullTerminatedString Integer Overflow — SKIPPED

## Why this vulnerability is skipped

### Vulnerability recap

`AP4_ByteStream::ReadNullTerminatedString` (Ap4ByteStream.cpp:353-368) uses an `unsigned int size` counter that starts at 0 and increments by 1 per byte read. Each iteration calls `buffer.SetDataSize(size+1)`. When `size == 0xFFFFFFFF`, the expression `size+1` wraps to 0 (unsigned overflow), causing `buffer.SetDataSize(0)` to free or shrink the buffer, and the subsequent write `buffer.UseData()[0xFFFFFFFF] = c` becomes a 1-byte heap out-of-bounds write.

### Trigger requirement

To reach the overflow, the loop must execute exactly 4,294,967,295 iterations without encountering a null byte (0x00). Each iteration reads one byte via `ReadUI08`. This means the input stream must supply 4,294,967,295 consecutive non-null bytes before a null terminator or EOF.

### Why a command-line MP4 cannot satisfy this

**Caller analysis**

The only callers of `ReadNullTerminatedString` in the Bento4 source reachable from `mp42aac` are in `AP4_SubtitleSampleEntry::ReadFields` (Ap4SampleEntry.cpp:1204-1208). This is invoked when the atom factory encounters an `stpp` box inside an `stsd` context.

**No SubStream bounding, but EOF terminates the loop**

The atom factory passes the raw file stream directly to the `AP4_SubtitleSampleEntry` constructor; no `AP4_SubStream` wrapper bounds it to the box size. However, when `ReadUI08` reaches end-of-file, it returns an error code, and the loop exits early (Ap4ByteStream.cpp:360). Therefore the total bytes read is limited by the physical file size, not the declared box size.

**64-bit sizes rejected for sample entries**

`AP4_AtomFactory::CreateAtomFromStream` (Ap4AtomFactory.cpp:270) returns `AP4_ERROR_INVALID_FORMAT` if the atom inside an `stsd` context has an extended (64-bit) size. The maximum declared size for an `stpp` box is therefore 0xFFFFFFFF bytes (~4 GB).

**File must be ~4 GB with no null bytes**

Even with the largest possible declared size, the file itself must be approximately 4 GB, and every byte of the string payload must be non-null. The counter reaches 0xFFFFFFFF only after reading 4,294,967,295 non-null bytes.

**Sparse file trick fails**

A sparse file created with `truncate -s 4G` is mostly unallocated. When the OS reads unallocated sparse regions, it returns zero bytes (0x00). A 0x00 byte is interpreted as the null terminator and exits the `do { ... } while (c)` loop immediately. Therefore, a sparse file cannot keep the loop running for 4 billion iterations.

**Conclusion**

There is no practical way to trigger this vulnerability by passing a command-line MP4 file:
- A real ~4 GB file of non-null bytes is required.
- Sparse files supply null bytes that terminate the loop prematurely.
- This makes the PoC infeasible in a command-line context.

### Source references

| File | Lines | Note |
|------|-------|------|
| Ap4ByteStream.cpp | 353-368 | Vulnerable function |
| Ap4SampleEntry.cpp | 1197-1211 | Only reachable caller path |
| Ap4AtomFactory.cpp | 268-270 | 64-bit size rejected for sample entries |
| Ap4AtomFactory.cpp | 215-218 | Atom size must not exceed bytes_available (file size) |
