# VULN-002 PoC Notes

## Vulnerability Summary

**Title**: Integer Overflow in `DecryptSampleData` Bounds Check Bypasses Buffer Guard Leading to Heap OOB Read/Write  
**Location**: `Bento4/Source/C++/Core/Ap4CommonEncryption.cpp`, line 1893  
**CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-Based Buffer Overflow)

## Root Cause

At line 1893 of `AP4_CencSingleSampleDecrypter::DecryptSampleData()`:

```c
if ((unsigned int)(in_end-in) < cleartext_size + encrypted_size)
    return AP4_ERROR_INVALID_FORMAT;
```

- `cleartext_size` is `AP4_UI16` (uint16, max 65535)
- `encrypted_size` is `AP4_UI32` (uint32, max 4294967295)

When summed with mixed types, the addition promotes to `unsigned int` (32-bit on most platforms):

```
cleartext_size=1 (UI16) + encrypted_size=0xFFFFFFFF (UI32)
= (unsigned int)(1 + 0xFFFFFFFF)
= (unsigned int)(0x100000000)
= 0x00000000  <- integer overflow! truncates to 0
```

The check becomes `any_positive_value < 0`, which is **always false** for unsigned integers. The bounds guard is completely bypassed.

## Exploitation Path

After bypass, line 1908 is reached:

```c
AP4_Result result = m_Cipher->ProcessBuffer(
    in + cleartext_size,   // in+1 (within small buffer)
    encrypted_size,        // 0xFFFFFFFF = ~4GB !!!
    out + cleartext_size,
    &encrypted_size,
    false
);
```

With `encrypted_size=0xFFFFFFFF`, `ProcessBuffer` attempts to read/write approximately 4GB of memory starting just 1 byte into a small heap buffer. This causes:
- **Heap OOB read** from the cipher input buffer
- **Heap OOB write** to the cipher output buffer

## Trigger Conditions

The vulnerable code requires:
1. A `senc` box with `flags=0x02` (UseSubSampleEncryptionMap enabled)
2. A subsample entry with `bytes_of_cleartext_data=1` (UI16) and `bytes_of_encrypted_data=0xFFFFFFFF` (UI32)
3. The `AP4_CencSingleSampleDecrypter::DecryptSampleData()` function must be called

## MP4 Structure Constructed

```
ftyp (iso5/dash/iso6)
moov
  mvhd
  trak
    tkhd (track_ID=1, audio)
    mdia
      mdhd (timescale=44100)
      hdlr (soun)
      minf
        smhd
        dinf
          dref
            url. (self-contained)
        stbl
          stsd
            enca (encrypted audio)
              [audio fields: ch=2, 16-bit, 44100Hz]
              sinf
                frma (mp4a)
                schm (cenc, v1.0)
                schi
                  tenc (isEncrypted=1, IV_size=16)
          stts (empty)
          stsc (empty)
          stco (empty)
          stsz (empty)
  mvex
    trex (track_ID=1)
moof
  mfhd (sequence=1)
  traf
    tfhd (track_ID=1, default-base-is-moof)
    trun (1 sample, size=4)
    senc (flags=0x02)         <--- VULNERABILITY TRIGGER
      sample_count=1
      IV: 16 zero bytes
      subsample_count=1
      bytes_of_cleartext=1    <-- UI16, small value
      bytes_of_encrypted=0xFFFFFFFF  <-- UI32, max value -> OVERFLOW
mdat
  DE AD BE EF (4 bytes of sample data)
```

## Why mp42aac Does Not Trigger the Crash

The `mp42aac` binary uses:
```c
// In DecryptAndWriteSamples():
AP4_SampleDecrypter* decrypter = AP4_SampleDecrypter::Create(pdesc, key, 16);
```

This calls `AP4_SampleDecrypter::Create(AP4_ProtectedSampleDescription*, const AP4_UI08*, AP4_Size, AP4_BlockCipherFactory*)` in `Ap4Protection.cpp` (line 735), which has the following switch:

```c
switch(sample_description->GetSchemeType()) {
    case AP4_PROTECTION_SCHEME_TYPE_OMA: ...
    case AP4_PROTECTION_SCHEME_TYPE_IAEC: ...
    default:
        return NULL;  // <-- CENC falls here, returns NULL
}
```

For CENC scheme type, this function returns `NULL`. The mp42aac code then prints "ERROR: unable to create decrypter" and returns early — the vulnerable `DecryptSampleData` at line 1893 is **never called**.

The vulnerable code path is reached via the **traf-aware** overload:
```c
AP4_SampleDecrypter::Create(AP4_ProtectedSampleDescription*, AP4_ContainerAtom* traf, ...)
```
which is used by tools like `mp4decrypt` and `AP4_CencDecryptingProcessor`, not by `mp42aac`.

## Expected Behavior When Run

- **Without `--key`**: mp42aac prints "ERROR: encrypted tracks require a key" — no crash.
- **With `--key`**: mp42aac calls `DecryptAndWriteSamples`, `AP4_SampleDecrypter::Create` returns NULL (cenc not supported), prints "ERROR: unable to create decrypter" — no crash.
- **ASAN log**: No ASAN errors expected, as the vulnerable function is never reached.

## Status: UNVERIFIED

The PoC correctly constructs the malicious data payload but mp42aac does not exercise the vulnerable code path. The crash would be triggered in:
1. `mp4decrypt` with a valid decryption key
2. Any code path that uses `AP4_CencDecryptingProcessor` or the traf-aware `AP4_SampleDecrypter::Create`
3. Fuzz testing that directly invokes `AP4_CencSingleSampleDecrypter::DecryptSampleData`
