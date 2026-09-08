I have completed the full analysis of `d3d12va_vc1.c`. Here is my audit conclusion:

**Summary of analysis:**

- **Lines 36-42**: `D3D12DecodePictureContext` — `bitstream_size` is `unsigned` (32-bit). `slices[]` is statically bounded by `MAX_SLICES=1024`.
- **Lines 77-79**: Slice count bounds-check against `MAX_SLICES` before array write — correct.
- **Line 89**: `ctx_pic->bitstream_size += size;` — `unsigned` + `uint32_t`, no overflow guard. Accumulates across up to 1024 slices.
- **Lines 165-167** (`d3d12va_vc1_end_frame`): The wrapped (too-small) `bitstream_size` is added to a properly cast `uint64_t` term and passed to `ff_d3d12va_common_end_frame` as `UINT64 bitstream_size`.
- **Line 665** (`d3d12va_get_valid_helper_objects`): D3D12 buffer is allocated with that (undersized) UINT64 value.
- **Lines 125-136** (`update_input_arguments`): `memcpy` loop writes `slice_count * sizeof(vc1_start_code) + sum(actual slice sizes)` bytes into the mapped buffer — if `bitstream_size` wrapped, this total exceeds the allocated buffer size → OOB write into GPU-mapped heap memory.

The overflow requires total per-frame slice data to exceed 4 GB (up to 1024 slices × ≤512 MB each), which is impractical in typical streams but technically constructable in a crafted bitstream.

## VULN: Integer overflow in bitstream_size accumulation leading to undersized D3D12 buffer and OOB write
- **漏洞类别**: memory-safety
- **函数**: d3d12va_vc1_decode_slice() / d3d12va_vc1_end_frame() / update_input_arguments()
- **行号**: 89 / 165-167 / 113-137
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted VC1/WMV3 media file
- **外部触发路径**: `ffmpeg -i <crafted.vc1> -hwaccel d3d12va -f null -` → `avcodec_send_packet()` → VC1 decoder → `d3d12va_vc1_decode_slice()` (累加 `bitstream_size` 发生 wrap) → `d3d12va_vc1_end_frame()` (将溢出后的小值作为 UINT64 传入) → `ff_d3d12va_common_end_frame()` → `d3d12va_get_valid_helper_objects()` (用溢出后的小尺寸分配 D3D12 GPU 上传缓冲区) → `update_input_arguments()` → `memcpy(mapped_ptr, ..., size)` OOB 写
- **描述**: `D3D12DecodePictureContext.bitstream_size` 字段类型为 `unsigned`（32 位），在 `d3d12va_vc1_decode_slice()` 的第 89 行以 `ctx_pic->bitstream_size += size` 累加每个切片的字节数，最多可累加 `MAX_SLICES=1024` 次。当所有切片的字节总量超过 `UINT32_MAX`（约 4 GB）时，`bitstream_size` 发生无符号整数回绕，变为一个远小于实际总量的值。在 `d3d12va_vc1_end_frame()` 中，这个已回绕的 `unsigned` 值被隐式零扩展为 `UINT64` 传入 `ff_d3d12va_common_end_frame()`，导致 D3D12 GPU 上传缓冲区（通过 `ID3D12Device_CreateCommittedResource` 分配）按此回绕后的小尺寸分配。随后 `update_input_arguments()` 中的循环（第 113–137 行）将实际的（远大于分配大小的）切片数据通过 `memcpy` 写入 `ID3D12Resource_Map` 返回的 `mapped_data` 指针，造成 GPU 上传缓冲区的越界写入。
- **触发条件**: 攻击者需构造一个 VC1 或 WMV3 媒体文件（如 `.vc1`、`.wmv` 或封装于 ASF 容器的流），使单帧包含多个切片（最多 1024 个），且所有切片的原始字节总量之和超过 4 GB（约 4,294,967,296 字节）；例如每个切片约 4 MB、共 1024 个切片即可触发。目标系统须启用 D3D12 硬件加速（Windows + 支持 VC1 DXVA 解码的 GPU）。
- **安全影响**: 越界写入 GPU 驱动映射的堆内存区域，最坏情况可导致远程代码执行（RCE）；若 GPU 驱动程序或内核对该映射区域具有写保护，则至少导致进程崩溃（DoS）。由于写入位置与 D3D12 分配的上传堆相邻，内存布局可被精心控制以实现可靠利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
