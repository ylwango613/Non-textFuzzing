# VULN 001 — NULL Dereference in av1_parser_parse via Dropped OBU Content

## Summary

**CWE**: CWE-476 (NULL Pointer Dereference)  
**File**: `libavcodec/av1_parser.c`, lines 101–113  
**Function**: `av1_parser_parse()`

## Vulnerable Code

```c
// av1_parser.c:101-113
for (int i = 0; i < td->nb_units; i++) {
    const CodedBitstreamUnit *unit = &td->units[i];
    const AV1RawOBU *obu = unit->content;   // ← can be NULL, NO null check!
    const AV1RawFrameHeader *frame;

    if (unit->type == AV1_OBU_FRAME)
        frame = &obu->obu.frame.header;     // NULL DEREF if obu==NULL
    else if (unit->type == AV1_OBU_FRAME_HEADER)
        frame = &obu->obu.frame_header;     // NULL DEREF if obu==NULL
    else
        continue;
```

The AV1 decoder (`av1dec.c`) has a null check at line 1251 (`if (!obu) continue;`),
but `av1_parser_parse()` is missing this guard.

## How unit->content Becomes NULL

`unit->content` is set to NULL (without returning an error) when `cbs_av1_read_unit()`
returns `AVERROR(EAGAIN)`. This happens via the operating point drop path
(`cbs_av1.c:879-888`):

```c
// cbs_av1.c:879-888
if (obu->header.obu_extension_flag) {
    if (obu->header.obu_type != AV1_OBU_SEQUENCE_HEADER &&
        obu->header.obu_type != AV1_OBU_TEMPORAL_DELIMITER &&
        priv->operating_point_idc) {            // ← must be != 0
        int in_temporal_layer =
            (priv->operating_point_idc >>  priv->temporal_id    ) & 1;
        int in_spatial_layer  =
            (priv->operating_point_idc >> (priv->spatial_id + 8)) & 1;
        if (!in_temporal_layer || !in_spatial_layer) {
            return AVERROR(EAGAIN);              // → cbs.c:202: content=NULL
        }
    }
}
```

Then in `cbs.c:198-203`:
```c
} else if (err == AVERROR(EAGAIN)) {
    av_log(...);
    av_refstruct_unref(&unit->content_ref);
    unit->content = NULL;         // ← content silently set to NULL, no error returned
```

Because no error is returned, `ff_cbs_read()` returns 0 (success), and
`av1_parser_parse()` proceeds to the for-loop at line 101, where `obu = NULL` leads
to the NULL pointer dereference.

## Trigger Conditions

1. **CBS operating_point_idc must be non-zero**: requires `priv->operating_point >= 0`
   (at `cbs_av1.c:901`) so the idc is updated from the sequence header.

2. **SEQUENCE_HEADER OBU** with `operating_point_idc[0] = 0x101`:
   - temporal_id=0 is covered (bit 0 set)
   - temporal_id=1 is NOT covered (bit 1 = 0)

3. **FRAME or FRAME_HEADER OBU** with `obu_extension_flag=1` and `temporal_id=1`:
   - Drop check: `(0x101 >> 1) & 1 = 0` → EAGAIN → `content=NULL`

## Why the Standard ffmpeg Binary Does Not Crash

The AV1 PARSER (`av1_parser.c`) initializes its CBS context via:
```c
// av1_parser_init (av1_parser.c:203)
ret = ff_cbs_init(&s->cbc, AV_CODEC_ID_AV1, NULL);
```

The CBS AV1 context option `operating_point` defaults to `-1`
(cbs_av1.c:1366-1367). With `operating_point = -1`, the guard at
`cbs_av1.c:901` prevents `operating_point_idc` from ever being set:

```c
// cbs_av1.c:901
if (priv->operating_point >= 0) {   // FALSE for parser (op=-1)
    priv->operating_point_idc = ...  // never reached!
}
```

Therefore `operating_point_idc` stays 0, the drop check is skipped, and OBUs are
never dropped in the parser context.

By contrast, the **AV1 Decoder** (`av1dec.c:895`) explicitly sets `operating_point=0`:
```c
av_opt_set_int(s->cbc->priv_data, "operating_point", s->operating_point, 0);
```
The decoder would crash without its own null check, but it has `if (!obu) continue;`
at line 1251 as protection.

## Execution Path Observed (IVF Test)

Using an IVF container (which bypasses the `av1_frame_merge` BSF used by the raw .av1
OBU demuxer), the AV1 parser IS invoked directly:

```
[av1 @ 0x519000000a80] Invalid value at reduced_tx_set: bitstream ended.
[av1 @ 0x519000000a80] Failed to read unit 2 (type 3): Invalid data found ...
[av1 @ 0x519000000a80] Failed to parse temporal unit.
```

The sequence header (unit 0) parsed successfully. The frame header (unit 2, type=3)
failed to parse because the 4-byte payload is not a valid frame header bitstream.
The CBS returns `AVERROR_INVALIDDATA` (not EAGAIN) → `av1_parser_parse` goes to
`goto end` before reaching the OBU loop → no null dereference.

## Conditions to Actually Trigger the Crash

For an application (not the ffmpeg command-line binary) using libavcodec directly:

```c
// Application must:
AVCodecParserContext *parser = av_parser_init(AV_CODEC_ID_AV1);
AV1ParseContext *s = parser->priv_data;
// Set operating_point=0 so CBS will drop OBUs with wrong temporal_id:
av_opt_set_int(s->cbc->priv_data, "operating_point", 0, 0);
// Then feed crafted input (sequence_header + frame_header with temporal_id=1)
// → CBS EAGAIN → content=NULL → av1_parser_parse NULL deref at line 103,109
```

## Input File Structure (vuln_001_input.ivf / vuln_001_input_raw.av1)

| OBU | Type | Ext | temporal_id | Role |
|-----|------|-----|-------------|------|
| Temporal Delimiter | 2 | No | 0 | Marks temporal unit start |
| Sequence Header | 1 | No | 0 | Sets idc=0x101 |
| Frame Header | 3 | Yes | **1** | tid=1 not covered by idc → EAGAIN |

## Proposed Fix

Add a null check in `av1_parser_parse()` before dereferencing `obu`:

```c
// av1_parser.c (proposed fix, analogous to av1dec.c:1251)
const AV1RawOBU *obu = unit->content;
if (!obu)
    continue;   // skip OBUs dropped by operating point filtering
```
