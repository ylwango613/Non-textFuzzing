Full analysis complete. The file is 153 lines; I've read every line and traced all arithmetic paths:

- **Line 46** `stride = avctx->width * 8 / 3`: signed overflow possible for very large width, but the resulting negative stride makes `line_end` point far before `avpkt->data`, so `line_end - src < 4` is immediately true and the loop breaks without reading anything.
- **Line 58** `avctx->height * stride` overflow: when stride derives from line 56 (`avpkt->size / height`), the product is always `≤ avpkt->size` by integer-division identity, so the real data never exceeds the packet regardless of overflow appearance.
- **Lines 80–86** inner pointer guards (`line_end - src < 4`): these are the effective safety mechanism; they prevent all within-line OOB reads regardless of stride/size arithmetic.
- **Lines 130–132** `memcpy` to frame: writes at most `width-x` luma and `(width-x+1)/2` chroma elements, which fit exactly within the 6/3/3-element temp arrays and within the ff_get_buffer-allocated frame planes.
- **Destination y/u/v pointers**: incremented at most 6/3/3 times per 6-pixel group, matching the YUV422 layout of the allocated frame.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
