# VULN 001 Analysis Notes — ff_dovi_rpu_generate() Heap Buffer Overflow

## Vulnerability Location
- **File**: `libavcodec/dovi_rpuenc.c`, lines 782-795, 863-869
- **Function**: `ff_dovi_rpu_generate()`

## Root Cause
At line 784, the buffer-size estimation hardcodes **177 bytes per MMR mapping segment**:
```c
case AV_DOVI_MAPPING_MMR: buffer_size += 177; break;
```
However, the actual bytes written per MMR segment (order=3) are:
```
set_ue_golomb(mapping_idc=1)           :   3 bits
put_bits(mmr_order_minus1=2)           :   2 bits
put_se_coef × 1  (mmr_constant)        :   se_golomb(ipart) + coef_log2_denom bits
put_se_coef × 21 (mmr_coef[3][7])      :   21 × (se_golomb(ipart) + coef_log2_denom bits)
```
With `coef_log2_denom = 48` and integer parts at ±0x7FFF (31-bit se_golomb):
```
5 + 22 × (31 + 48) = 5 + 22 × 79 = 1743 bits ≈ 218 bytes  > 177 bytes allocated
```

## Why the File-Based Trigger Path Fails

### RPU Decoder Validation (`dovi_rpudec.c`, line 436)
```c
hdr->coef_log2_denom = get_ue_golomb(gb);
VALIDATE(hdr->coef_log2_denom, 13, 32);   // HARD CAP AT 32
```
The `VALIDATE` macro calls `ff_dovi_ctx_unref(s)` and returns `AVERROR_INVALIDDATA`
for any value outside [13, 32]. A crafted RPU NAL with `coef_log2_denom = 48`
(or any value > 32) is **rejected at parse time** before it ever reaches the encoder.

### Arithmetic With the Parser Cap (coef_log2_denom = 32, worst case)
```
Per put_se_coef:  se_golomb(0x7FFF) = 31 bits  +  32 fractional bits  = 63 bits
Per MMR segment:  3 + 2 + 22 × 63 = 1391 bits  =  173.9 bytes  <  177 bytes
```
The 177-byte allocation is **sufficient** for all values reachable through the
decoder's validated range. The overflow only manifests at `coef_log2_denom ≥ ~45`.

### Available Encoder Entry Points (all protected by parser validation)
| Code path | How metadata reaches encoder | coef_log2_denom source |
|-----------|------------------------------|------------------------|
| `dovi_rpu` BSF | Parsed by `ff_dovi_rpu_parse` → `ff_dovi_get_metadata` | Capped to 32 |
| libx265 encoder | Frame side data set by HEVC decoder's `ff_dovi_rpu_parse` | Capped to 32 |
| libaom encoder | Same as libx265 | Capped to 32 |
| libsvtav1 encoder | Same as libx265 | Capped to 32 |

There is **no command-line-accessible path** that allows injecting
`coef_log2_denom > 32` into `ff_dovi_rpu_generate`.

## Conclusion
The vulnerability is **not triggerable** via a crafted media file passed to the
`ffmpeg` command-line tool. Exploiting it would require calling
`ff_dovi_rpu_generate` directly with a programmatically constructed
`AVDOVIMetadata` structure containing `coef_log2_denom = 48` — i.e., it is only
reachable from a custom C/C++ harness, not from a media file.

**Status: SKIPPED**
