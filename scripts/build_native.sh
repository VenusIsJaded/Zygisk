#!/bin/bash
# Build all 4 Android ABIs.
set -e

export PATH="/home/z/my-project/tools/cmake-3.29.6-linux-x86_64/bin:$PATH"
NDK=/home/z/my-project/tools/android-ndk-r27c
SRC=/home/z/my-project/zygisnext_reimpl
OUT=/home/z/my-project/zygisnext_reimpl/dist

rm -rf $OUT
mkdir -p $OUT

for ABI in arm64-v8a armeabi-v7a x86_64 x86; do
    echo "=== Building $ABI ==="
    BUILD=$SRC/build_$ABI
    rm -rf $BUILD
    mkdir -p $BUILD
    cd $BUILD
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
        -DANDROID_ABI=$ABI \
        -DANDROID_PLATFORM=android-29 \
        -DCMAKE_BUILD_TYPE=Release \
        2>&1 | tail -5
    make -j4 2>&1 | tail -5

    # Copy outputs to dist
    DIST=$OUT/$ABI
    mkdir -p $DIST
    cp native/zygiskd/zygiskd $DIST/
    cp native/libzygisk/libzygisk.so $DIST/
    cp native/libzn_loader/libzn_loader.so $DIST/
    cp native/libpayload/libpayload.so $DIST/
    echo "=== $ABI done ==="
    ls -la $DIST
done
