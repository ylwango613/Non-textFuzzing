# VULN 001 — Integer Overflow in AP4_CencSampleInfoTable Constructor

## Vulnerability Summary

**CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-Based Buffer Overflow)

**Root cause**: In `AP4_CencSampleInfoTable::AP4_CencSampleInfoTable()` (Ap4CommonEncryption.cpp line 3007):

```cpp
m_IvData.SetDataSize(m_IvSize * sample_count);
AP4_SetMemory(m_IvData.UseData(), 0, m_IvSize * sample_count);
```

`m_IvSize` is `AP4_UI08` (max 255) and `sample_count` is `AP4_UI32`.  
With `m_IvSize = 16` and `sample_count = 0x10000000` (268,435,456):

- `16 × 0x10000000 = 0x100000000` — overflows 32-bit to **0**
- `SetDataSize(0)` → buffer stays NULL (`m_IvData.m_Buffer = NULL`)
- `SetIv(i, data)` (line 3336 in `CreateSampleInfoTable`) → `memcpy(NULL, data, 16)` → **heap OOB write / NULL deref**

## Malicious File Structure

The generated `vuln_001.mp4` is a fragmented MP4 (738 bytes) with:

| Box Path | Key Field | Value |
|---|---|---|
| `moov/trak/mdia/minf/stbl/stsd/enca/sinf/schm` | scheme_type | `cenc` |
| `moov/trak/mdia/minf/stbl/stsd/enca/sinf/schi/tenc` | default_is_protected | 1 |
| `moov/trak/mdia/minf/stbl/stsd/enca/sinf/schi/tenc` | default_per_sample_iv_size | 16 |
| `moof/traf/senc` | **sample_count** | **0x10000000** |
| `moof/traf/senc` | IV payload | 16 bytes (zeros) |

The `senc` atom declares 268,435,456 samples but contains only one real IV (16 bytes). The `sample_count` field is stored as `m_SampleInfoCount = 0x10000000` in the `AP4_CencSampleEncryption` object.

## Call Chain for Crash (Full)

```
AP4_File::ParseStream
  └── atom_factory.CreateAtomFromStream(moof)
        └── moof/traf/senc → AP4_SencAtom::Create()
              └── AP4_CencSampleEncryption::AP4_CencSampleEncryption(size, stream)
                    reads: m_SampleInfoCount = 0x10000000  [stored, no crash yet]
                    reads: m_SampleInfos = 16 bytes of IV

... (later, during decryption) ...

AP4_CencSampleDecrypter::Create(sample_description, traf, ...)
  └── AP4_CencSampleInfoTable::Create(sample_description, traf, ...)
        └── sample_encryption_atom->CreateSampleInfoTable(0, 0, 0, 16, 0, NULL, table)
              └── new AP4_CencSampleInfoTable(0, 0, 0, 0x10000000, 16)  ← OVERFLOW
                    m_IvData.SetDataSize(16 * 0x10000000)  → SetDataSize(0)
                    [m_IvData.m_Buffer = NULL, m_DataSize = 0]
              └── for i in range(0x10000000):
                    data_size(16) >= per_sample_iv_size(16) → true
                    table->SetIv(0, data)          ← CRASH
                      dst = m_IvData.UseData() + 0 = NULL
                      memcpy(NULL, data, 16)        ← OOB WRITE / SEGV
```

## Why mp42aac Does NOT Trigger the Crash

`mp42aac`'s `DecryptAndWriteSamples()` calls:

```cpp
AP4_SampleDecrypter* decrypter = AP4_SampleDecrypter::Create(pdesc, key, 16);
```

This is the **no-traf variant** of `AP4_SampleDecrypter::Create` (Ap4Protection.cpp line 735), which only handles `OMA` and `IAEC` (ISMA) schemes:

```cpp
switch(sample_description->GetSchemeType()) {
    case AP4_PROTECTION_SCHEME_TYPE_OMA:  { ... }
    case AP4_PROTECTION_SCHEME_TYPE_IAEC: { ... }
    default: return NULL;  // ← CENC returns NULL here
}
```

For `CENC` (`'cenc'`) scheme, `NULL` is returned, and mp42aac prints "ERROR: unable to create decrypter" and exits without ever reaching `AP4_CencSampleDecrypter::Create`.

The **traf-aware** variant (Ap4Protection.cpp line 781) DOES handle CENC:

```cpp
case AP4_PROTECTION_SCHEME_TYPE_CENC: {
    AP4_CencSampleDecrypter::Create(sample_description, traf, ...);  // → crash
}
```

But mp42aac never calls this variant. It is used by `AP4_CencDecryptingProcessor` (the encryption/decryption pipeline) which is invoked by other Bento4 tools (e.g., mp4decrypt).

## Expected Behavior With a Crash-Capable Caller

When called with `mp4decrypt` or via `AP4_CencDecryptingProcessor` on this file:
1. ASAN detects **heap-buffer-overflow** at `memcpy(NULL, data, 16)`
2. Or: **SEGV** / null-pointer dereference at write address 0x0

## PoC Execution Result

- mp42aac exits with "ERROR: unable to create decrypter" (no crash)
- No ASAN/UBSAN output
- Status: **UNVERIFIED** — the vulnerability exists in the code, but this binary
  does not reach the vulnerable code path for CENC-encrypted content
