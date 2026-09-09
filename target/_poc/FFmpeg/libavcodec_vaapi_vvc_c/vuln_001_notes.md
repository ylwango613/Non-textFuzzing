# VULN 1 – Heap OOB Read in get_slice_data_byte_offset (vaapi_vvc.c)

## Status: SKIPPED

## Reason

This vulnerability is located in `get_slice_data_byte_offset()` at lines 484–507 of
`/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/vaapi_vvc.c`.

The function is called only from `vaapi_vvc_decode_slice()`, which is registered as the
`.decode_slice` callback for the VAAPI-accelerated VVC decoder (`vvc_vaapi`). It is
**never** executed when decoding via the software VVC decoder.

### Trigger requirements

| Requirement | Status on this machine |
|---|---|
| ffmpeg compiled with VAAPI support | NOT MET – `ffmpeg -hwaccels` returns an empty list; `ldd` shows no `libva*.so` |
| VAAPI user-space driver (libva) installed | NOT MET – `vainfo` is not available |
| Compatible GPU with VAAPI VVC decode support (e.g., Intel Arc) | Unknown, but moot |

### Evidence collected

```
$ /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels
Hardware acceleration methods:
(empty)

$ ldd /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg | grep -i vaapi
(no output)

$ /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -decoders | grep -i vaapi
(no output – only software "vvc" decoder present)
```

### Why the vulnerability cannot be triggered without VAAPI

Even with a perfectly crafted VVC/H.266 bitstream, FFmpeg will route decoding through
the software decoder (`vvc`), not through `vvc_vaapi`. The function
`get_slice_data_byte_offset()` will never be reached. No crafted file alone can force
execution into the VAAPI code path when the binary was compiled without VAAPI support.

## Vulnerability description (for reference)

`get_slice_data_byte_offset()` iterates over the raw NAL unit buffer looking for the
start of slice data. Inside the inner loop (line 495), the index `i + j + skip_bytes`
is computed without any upper-bound check against `size`. If the slice header data
(`slice->data`) is crafted so that a match is never found near the end of the buffer,
the index can advance past `size`, causing a heap out-of-bounds read. Under ASAN this
would produce a `heap-buffer-overflow` report; on a production build it can leak memory
content or crash.

**CWE**: CWE-125 (Out-of-Bounds Read)  
**Attack vector**: crafted VVC/H.266 bitstream fed to `ffmpeg -hwaccel vaapi`  
**Affected lines**: 484–507 of `libavcodec/vaapi_vvc.c`
