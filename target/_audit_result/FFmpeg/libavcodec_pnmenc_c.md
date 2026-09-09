I have now done a thorough analysis of `pnmenc.c`:

**Analysis summary:**

1. **Buffer allocation** (line 43–49): `av_image_get_buffer_size` performs full overflow checking (`av_image_check_size`, `av_image_fill_linesizes`, `av_image_fill_plane_sizes`, plus a per-plane INT_MAX guard). The result is checked for `< 0` before use. Adding `200U` for the header cannot overflow because `ff_get_encode_buffer` takes `int64_t` and explicitly rejects values > `INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE`.

2. **Pixel write loops** (lines 138–220): Every branch writes at most `size` bytes of pixel data plus ≤ 30 bytes of text header — always within the `size + 200` allocation:
   - GBRPF32 PFM: `12 × width × height` written = equals `av_image_get_buffer_size` for the 3-plane float format.
   - GRAYF32 PFM: `4 × width × height`.
   - GBRPF32 PHM: `6 × width × height` < `12 × width × height` (buffer).
   - GRAYF32 PHM: `2 × width × height` < `4 × width × height` (buffer).
   - Packed formats (GRAY8/16, RGB24/48, MONO): `n × h` exactly equals `av_image_get_buffer_size`.

3. **YUV420P/YUV420P16BE UV section** (lines 208–220): After `h >>= 1` and `n >>= 1`, total UV bytes written match the plane sizes computed by `av_image_get_buffer_size`.

4. **`n` integer overflow** (e.g. `width * 6` for RGB48BE): Pre-empted by `av_image_get_buffer_size` detecting the equivalent overflow and returning an error first; the line 46–47 check exits before `n` is ever used.

5. **snprintf header writes**: All bounded by `bytestream_end - bytestream` with known-small format strings (`%d` for int, `%f` for a fixed ±1.0).

6. **This is an encoder**: It takes already-decoded `AVFrame` data as input, not raw file bytes. An attacker cannot feed untrusted binary directly into this function; the `AVFrame` properties are constrained by the preceding decoder.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
