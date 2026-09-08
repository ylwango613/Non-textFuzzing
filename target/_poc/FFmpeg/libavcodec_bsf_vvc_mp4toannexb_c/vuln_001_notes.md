# VULN 001 — SKIPPED

## Vulnerability

`size_t`-to-`int` truncation of `new_extradata_size` at line 182 of
`/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/bsf/vvc_mp4toannexb.c`.

If `new_extradata_size > INT_MAX`, assigning it to `ctx->par_out->extradata_size`
(type `int`) produces a negative integer. This negative value then propagates into
`vvc_mp4toannexb_filter()`, bypassing the overflow guard at line 288 and causing
`memcpy` at line 300 to receive a negative `extra_size` promoted to a huge `size_t`,
leading to a heap buffer overflow.

## Why SKIPPED

### Minimum input size requirement: ~2.15 GB

The NALU length in the vvcC extradata is encoded as a 16-bit big-endian field
(`bytestream2_get_be16()`), giving a maximum of 65,535 bytes per NALU. Each NALU
contributes `4 + nalu_len` bytes to `new_extradata_size` (4-byte start code + data).

To overflow `INT_MAX = 2,147,483,647`:

    ceil(2,147,483,648 / (4 + 65535)) = ceil(2,147,483,648 / 65,539) ≈ 32,769 NALUs

Each such NALU requires 2 bytes (length field) + 65,535 bytes in the raw vvcC input:

    32,769 × 65,537 ≈ 2,148,139,873 bytes ≈ 2.15 GB

The vvcC box is stored in the codec extradata (moov/trak/.../stsd), so a 2.15 GB+
MP4 file is needed just for the container overhead, before any media data.

### Memory allocation infeasible in practice

Even if a 2 GB+ file were constructed:

1. FFmpeg reads the entire extradata into memory before parsing. A 2 GB+ allocation
   for the input extradata itself would be required.
2. `av_reallocp` inside the NALU loop would need to allocate another 2 GB+ for the
   reformatted (Annex B) extradata.
3. On typical systems this combined ~4 GB+ allocation is extremely likely to fail
   with ENOMEM, causing an error return before the truncation is reached.

### memcpy crash is not ASAN-reportable

Even under the unlikely scenario where all allocations succeed and the truncation
occurs, the subsequent `memcpy` at line 300 receives `extra_size` as a negative int
promoted to `size_t` (e.g., `0xFFFFFFFF80000000` for `-2147483648`). A memcpy of
~2^63 bytes does not produce an ASAN heap-buffer-overflow report; it either:
- Causes an immediate SIGSEGV when the copy crosses an unmapped page, or
- Causes the kernel to deliver SIGKILL due to the process trying to fault in
  petabytes of pages.

In neither case does ASAN have time to produce a structured report before the
process is terminated by the OS.

## Conclusion

The trigger requires a multi-gigabyte crafted input file, needs 4+ GB of heap
during parsing, and the resulting crash kills the process before ASAN can report.
The vulnerability is theoretically correct but practically impossible to demonstrate
via `ffmpeg` command-line file input.
