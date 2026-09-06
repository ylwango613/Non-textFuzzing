# Compile Commands

所有项目使用 `-fsanitize=address,undefined -g0 -fno-omit-frame-pointer` 编译，输出到各自的 `build_test/` 目录。

## 二进制文件位置汇总

| 项目 | 二进制绝对路径 | 大小 |
|------|--------------|------|
| jhead | `/data/ylwang/non-textfuzz/target/jhead/build_test/jhead` | 930 KB |
| flvmeta | `/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta` | 2.2 MB |
| exiv2 | `/data/ylwang/non-textfuzz/target/exiv2/build_test/bin/exiv2` | 18 MB |
| FFmpeg | `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` | 588 MB |
| FFmpeg | `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffprobe` | 583 MB |
| mp3rgain | `/data/ylwang/non-textfuzz/target/mp3rgain/build_test/mp3rgain` | 7.4 MB |
| gdk | `/data/ylwang/non-textfuzz/target/gdk/build_test/cmake_build/libgreen_gdk_full.a` | 564 MB |

> **exiv2 前置依赖**（已编译，无需重复）：
> - inih r58 → `/data/ylwang/non-textfuzz/target/tool/inih-install/`
> - fmt 12.0.0 → `/data/ylwang/non-textfuzz/target/tool/fmt-install/`

---

---

## jhead

**构建系统**: Makefile  
**输出**: `/data/ylwang/non-textfuzz/target/jhead/build_test/jhead`

```bash
cd /data/ylwang/non-textfuzz/target/jhead
mkdir -p build_test
make CC=gcc \
  CFLAGS="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  LDFLAGS="-fsanitize=address,undefined" \
  -j$(nproc)
cp jhead build_test/
```

---

## flvmeta

**构建系统**: CMake  
**输出**: `/data/ylwang/non-textfuzz/target/flvmeta/build_test/src/flvmeta`

```bash
cd /data/ylwang/non-textfuzz/target/flvmeta
mkdir -p build_test && cd build_test
cmake .. \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## exiv2

**构建系统**: CMake  
**输出**: `/data/ylwang/non-textfuzz/target/exiv2/build_test/bin/exiv2`  
**依赖**: inih 和 fmt 需手动编译（无 root）

### 第一步：编译 inih

```bash
TOOL=/data/ylwang/non-textfuzz/target/tool
INIH_SRC=$TOOL/inih-r58       # 从 https://github.com/benhoyt/inih/archive/r58.tar.gz 解压
INIH_PREFIX=$TOOL/inih-install

mkdir -p $INIH_PREFIX/{lib,include}
gcc -c $INIH_SRC/ini.c -I$INIH_SRC -o $TOOL/ini.o -fPIC
ar rcs $INIH_PREFIX/lib/libinih.a $TOOL/ini.o
g++ -c $INIH_SRC/cpp/INIReader.cpp -I$INIH_SRC -o $TOOL/INIReader.o -fPIC
ar rcs $INIH_PREFIX/lib/libINIReader.a $TOOL/INIReader.o
cp $INIH_SRC/ini.h $INIH_SRC/cpp/INIReader.h $INIH_PREFIX/include/
```

### 第二步：编译 fmt

```bash
FMT_PREFIX=/data/ylwang/non-textfuzz/target/tool/fmt-install
# 从 https://github.com/fmtlib/fmt/archive/12.0.0.tar.gz 解压到 tool/fmt-12.0.0
cd /data/ylwang/non-textfuzz/target/tool/fmt-12.0.0
mkdir -p build && cd build
cmake .. \
  -DCMAKE_INSTALL_PREFIX="$FMT_PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-fPIC" \
  -DCMAKE_CXX_FLAGS="-fPIC" \
  -DFMT_TEST=OFF -DFMT_DOC=OFF
make -j$(nproc) install
```

### 第三步：编译 exiv2

```bash
INIH_PREFIX=/data/ylwang/non-textfuzz/target/tool/inih-install
FMT_PREFIX=/data/ylwang/non-textfuzz/target/tool/fmt-install

cd /data/ylwang/non-textfuzz/target/exiv2
mkdir -p build_test && cd build_test
cmake .. \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_BUILD_TYPE=Release \
  -DEXIV2_BUILD_SAMPLES=OFF \
  -DEXIV2_BUILD_UNIT_TESTS=OFF \
  -DCMAKE_PREFIX_PATH="$FMT_PREFIX;$INIH_PREFIX" \
  -Dinih_INCLUDE_DIR="$INIH_PREFIX/include" \
  -Dinih_inireader_INCLUDE_DIR="$INIH_PREFIX/include" \
  -Dinih_LIBRARY="$INIH_PREFIX/lib/libinih.a" \
  -Dinih_inireader_LIBRARY="$INIH_PREFIX/lib/libINIReader.a"
make -j$(nproc)
```

---

## FFmpeg

**构建系统**: configure + make  
**输出**: `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg`, `ffprobe`

```bash
cd /data/ylwang/non-textfuzz/target/FFmpeg
mkdir -p build_test && cd build_test
../configure \
  --cc=gcc \
  --cxx=g++ \
  --extra-cflags="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  --extra-cxxflags="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  --extra-ldflags="-fsanitize=address,undefined" \
  --disable-optimizations \
  --disable-stripping \
  --enable-debug=0 \
  --disable-x86asm \
  --disable-doc
make -j$(nproc)
```

---

## mp3rgain

**构建系统**: Cargo (Rust)  
**输出**: `/data/ylwang/non-textfuzz/target/mp3rgain/build_test/mp3rgain`  
**注意**: ASAN 完全引入（`-Zsanitizer=address`，需 nightly）；UBSAN 仅链接 runtime（`-C link-args=-fsanitize=undefined`），Rust 代码本身无 LLVM 级插桩（Rust `-Zsanitizer` 不支持 `undefined`）

```bash
# 安装 nightly 工具链（仅需一次）
rustup toolchain install nightly --target x86_64-unknown-linux-gnu --profile minimal

cd /data/ylwang/non-textfuzz/target/mp3rgain
mkdir -p build_test
RUSTFLAGS="-Zsanitizer=address -C link-args=-fsanitize=undefined" \
  cargo +nightly build --release --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/mp3rgain build_test/
```

---

## gdk

**构建系统**: 自有 builddeps.sh + CMake  
**输出**: `/data/ylwang/non-textfuzz/target/gdk/build_test/cmake_build/libgreen_gdk_full.a`  
**注意**: 需先用官方脚本编译全部依赖（libwally-core, openssl, boost 1.87.0, tor, sqlite3 等共 15 个库）

### 第一步：编译所有依赖

```bash
cd /data/ylwang/non-textfuzz/target/gdk
mkdir -p build_test/deps
./tools/builddeps.sh --gcc --prefix build_test/deps \
  > build_test/builddeps.log 2>&1
```

### 第二步：编译 gdk

```bash
GDK_DEPS=/data/ylwang/non-textfuzz/target/gdk/build_test/deps

cd /data/ylwang/non-textfuzz/target/gdk
mkdir -p build_test/cmake_build && cd build_test/cmake_build
cmake ../.. \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g0 -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$GDK_DEPS" \
  -DENABLE_TESTS=OFF
make -j$(nproc)
```

