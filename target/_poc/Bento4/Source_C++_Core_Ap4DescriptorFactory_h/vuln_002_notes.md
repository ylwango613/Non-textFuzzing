# VULN 002 – Integer Underflow in AP4_EsDescriptor (OOB Read)

## Summary

**CWE-191 → CWE-125**: Unsigned integer underflow when computing the SubStream
size in `AP4_EsDescriptor::AP4_EsDescriptor(stream, header_size, payload_size)`
(`Ap4EsDescriptor.cpp`), caused by more bytes being consumed than the declared
`payload_size`, creating a ~4 GB SubStream that reads past the descriptor's
declared boundary.

## Root Cause

```cpp
// Ap4EsDescriptor.cpp
AP4_Position start;
stream.Tell(start);

stream.ReadUI16(m_EsId);          // 2 bytes
stream.ReadUI08(bits);            // 1 byte  →  3 consumed so far
m_Flags = (bits >> 5) & 7;

if (m_Flags & AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY) {
    stream.ReadUI16(m_DependsOn); // 2 more bytes  →  5 consumed total
}

AP4_Position offset;
stream.Tell(offset);

// UNDERFLOW: 4 (payload_size) - 5 (consumed) = 0xFFFFFFFF as AP4_Size (uint32)
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size - AP4_Size(offset - start));
```

When `flags = 0x20` (`m_Flags = 1`, STREAM_DEPENDENCY set):
- 5 bytes consumed: ES_ID(2) + flags(1) + DependsOn(2)
- declared `payload_size = 4`
- `4 - 5` as `uint32_t` = **0xFFFFFFFF**

The resulting SubStream has size 0xFFFFFFFF, so the `while` loop that calls
`CreateDescriptorFromStream(*substream, …)` can read far past the legitimate
end of the ES_Descriptor's payload.

## PoC Approach

1. Build a minimal MP4: `ftyp + moov(mvhd + trak(tkhd + mdia(mdhd + hdlr +
   minf(smhd + dinf + stbl(stsd(mp4a(esds)))))))`.

2. Inside `esds`, place an ES_Descriptor with:
   - tag = `0x03`, size byte = `0x04` (payload_size = 4)
   - payload: `[0x00 0x01]` ES_ID=1, `[0x20]` flags (STREAM_DEPENDENCY),
     `[0x00]` DependsOn-high (byte 3, last declared byte),
     `[0x00]` DependsOn-low  (byte 5 consumed — one past declared end)

3. Immediately after those 6 declared bytes, place a fake DecoderSpecificInfo
   descriptor: tag=`0x05`, expandable size `0xFF 0xFF 0xFF 0x7F` = 0x0FFFFFFF.

4. The overflowed SubStream (size=0xFFFFFFFF, anchored 1 byte past the ES
   payload end) reads this fake descriptor:
   - `SetDataSize(0x0FFFFFFF)` allocates 268 MB for `m_Info`.
   - `stream.Read(m_Info.UseData(), 0x0FFFFFFF)` is called.
   - The SubStream clamps the read to `0xFFFFFFFF − 5 = 0xFFFFFFFA` bytes,
     which **exceeds** the 0x0FFFFFFF-byte allocation → OOB write region.
   - In practice the file is tiny, so only the few remaining file bytes are
     written (bounded by EOF), but the sanitiser can observe the illegal
     access pattern. If allocation of 268 MB fails, `UseData()` returns NULL
     and the subsequent `Read(NULL, …)` causes a null-pointer dereference that
     ASAN reports immediately.

## Expected Output

With ASAN+UBSAN (`-fsanitize=address,undefined`), one of:

- **ASAN null-pointer dereference** — if the 268 MB allocation fails:
  ```
  ASAN: null-deref on address 0x000000000000 …
  READ of size … at 0x000000000000
  ```
- **Process exits normally** with no crash if the allocation succeeds and the
  file exhausts before the allocated buffer boundary (UNVERIFIED in that case).
- The integer underflow itself is not directly reported by UBSAN because
  `AP4_Size` is unsigned (`uint32_t`) and UBSAN does not flag unsigned overflow
  without `-fsanitize=unsigned-integer-overflow`.

## Files

| File | Purpose |
|------|---------|
| `vuln_002_gen.py` | Generates `vuln_002.mp4` |
| `vuln_002_run.sh` | Runs mp42aac under ASAN and collects output |
| `vuln_002.mp4`    | Malicious MP4 file (generated) |
| `vuln_002_result.txt` | Combined stdout/stderr + ASAN log |
| `vuln_002_status.txt` | `VERIFIED_CRASH` / `UNVERIFIED` / `ERROR` |
