After complete analysis of the 85-line `assdec.c` file and its full calling context:

- **`ass_decode_init` (`extradata_size + 1` allocation)**: `avcodec_open2` at `avcodec.c:177` validates `extradata_size < 0` and `>= FF_MAX_EXTRADATA_SIZE` and returns `AVERROR(EINVAL)` before the codec `init` callback is ever invoked, so neither signed integer overflow nor negative-size memcpy is reachable.
- **`av_strdup(avpkt->data)` (line 57)**: `av_strdup` calls `strlen` internally; however, FFmpeg's `AV_INPUT_BUFFER_PADDING_SIZE` (64 zero bytes) convention guarantees a null terminator beyond packet data for all normally-allocated packets (`av_new_packet`), and `av_strdup` itself handles `NULL` input safely. No exploitable OOB read is reachable via a crafted media file on this path.
- **`sub->rects` allocation (lines 49–55)**: Allocates exactly one pointer slot and one rect; `sub->num_rects = 1` is consistent; no OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
