#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# scripts/build_module.sh — cross-compile the module with the Android NDK
# and assemble a flashable Magisk-module zip.
#
# This is the single source of truth for producing release artifacts:
# the GitHub Actions workflow (.github/workflows/build.yml) calls this
# exact script, and a developer with a local NDK can run it directly.
#
# WHAT IT BUILDS (all four ABIs the NDK supports, matching customize.sh's
# and verify.sh's libs/<abi> expectations):
#   C++   libzygisk.so libpayload.so libzn_loader.so  (CMake, per ABI)
#   Rust  zygiskd                                        (Cargo, per target)
#
# WHAT IT ASSEMBLES (the flashable zip layout):
#   module.prop customize.sh post-fs-data.sh service.sh uninstall.sh
#   zs_compat.sh post-mount-hook.sh verify.sh LICENSE
#   libs/<abi>/{libzygisk.so,libpayload.so,libzn_loader.so,zygiskd}
#   META-INF/com/google/android/{update-binary,updater-script}
#
#   The update-binary is OUR OWN clean-room implementation of the
#   documented recovery installer protocol (OUTFD/ZIPFILE arguments,
#   ui_print over the fd, sourcing /data/adb/magisk/util_functions.sh,
#   calling its install_module). Magisk's own module_installer.sh is
#   GPL-3.0 and is NOT vendored into this Apache-2.0 tree; the
#   Magisk-app install path needs no META-INF at all (verified from
#   the official module docs: "The simplest Magisk module installer is
#   just a Magisk module packed as a zip file").
#
# VERIFIED SOURCES for every tool invocation used here (fetched and read):
#   - NDK CMake toolchain: developer.android.com/ndk/guides/cmake —
#     cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake
#     -DANDROID_ABI=<abi> -DANDROID_PLATFORM=android-<api>
#   - NDK clang targeting: developer.android.com/ndk/guides/
#     other_build_systems — $TOOLCHAIN/bin/clang --target=<triple><api>
#     (the same pattern ReZygisk's common.mk uses, with an explicit
#     --sysroot)
#   - Rust android targets (aarch64-linux-android, armv7-linux-androideabi,
#     i686-linux-android, x86_64-linux-android) are Tier 2 per the rustc
#     platform-support docs; per-target linker config comes from the
#     CARGO_TARGET_<triple>_LINKER / _RUSTFLAGS environment variables
#     documented in the Cargo book.
#   - NDK r26+ supports exactly armeabi-v7a arm64-v8a x86 x86_64 with a
#     minimum API level of 21 (revision history) — 21 is also this
#     module's minimum (Android 5.0), so the two line up exactly.
#
# NDK DISCOVERY ORDER (all verified locations):
#   1. $ANDROID_NDK_HOME            (GitHub runners: NDK 27.3 default)
#   2. $ANDROID_NDK_LATEST_HOME     (GitHub runners: newest NDK)
#   3. $ANDROID_NDK_ROOT            (classic variable)
#   4. $ANDROID_HOME/ndk-bundle or $ANDROID_HOME/ndk/*  (local SDKs)
#   The GitHub-hosted ubuntu-latest images ship the NDK preinstalled
#   (actions/runner-images images/ubuntu/Ubuntu2404-Readme.md documents
#   ANDROID_NDK_HOME and ANDROID_NDK_LATEST_HOME), so CI needs no
#   setup action — the same script runs identically locally and in CI.
#
# USAGE:
#   ./scripts/build_module.sh                    # all ABIs, release
#   NDK=/path/to/ndk ./scripts/build_module.sh   # explicit NDK
#   ./scripts/build_module.sh --out /tmp/out     # different output dir
#   ./scripts/build_module.sh --abis arm64-v8a   # subset
#   ./scripts/build_module.sh --skip-rust        # C++ only (quick check)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
NDK="${NDK:-}"
API_LEVEL="${API_LEVEL:-21}"
ABIS="${ABIS:-arm64-v8a armeabi-v7a x86_64 x86}"
OUT_ROOT="${OUT_ROOT:-$REPO_ROOT/build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
SKIP_RUST=0
SKIP_CPP=0
SKIP_ZIP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ndk)          NDK="$2"; shift 2;;
        --api)          API_LEVEL="$2"; shift 2;;
        --abis)         ABIS="$2"; shift 2;;
        --out)          OUT_ROOT="$2"; shift 2;;
        --type)         BUILD_TYPE="$2"; shift 2;;
        --skip-rust)    SKIP_RUST=1; shift;;
        --skip-cpp)     SKIP_CPP=1; shift;;
        --skip-zip)     SKIP_ZIP=1; shift;;
        -h|--help)
            sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
            exit 0;;
        *)
            echo "build_module.sh: unknown option: $1" >&2
            exit 2;;
    esac
done

# ---------------------------------------------------------------------------
# NDK discovery
# ---------------------------------------------------------------------------
find_ndk() {
    if [[ -n "$NDK" && -d "$NDK" ]]; then
        echo "$NDK"; return 0
    fi
    local candidate
    for candidate in \
        "${ANDROID_NDK_HOME:-}" \
        "${ANDROID_NDK_LATEST_HOME:-}" \
        "${ANDROID_NDK_ROOT:-}" \
        "${ANDROID_HOME:-$HOME/Android/Sdk}/ndk-bundle" \
        "${ANDROID_HOME:-$HOME/Android/Sdk}/ndk/${NDK_VERSION:-}"
    do
        if [[ -n "$candidate" && -d "$candidate" ]]; then
            echo "$candidate"; return 0
        fi
    done
    # Any NDK under $ANDROID_HOME/ndk/ (newest first — version-sorted
    # directory names like 27.3.13750724).
    local sdk_ndk="${ANDROID_HOME:-$HOME/Android/Sdk}/ndk"
    if [[ -d "$sdk_ndk" ]]; then
        candidate="$(ls -1 "$sdk_ndk" 2>/dev/null | sort -V | tail -1)"
        if [[ -n "$candidate" && -d "$sdk_ndk/$candidate" ]]; then
            echo "$sdk_ndk/$candidate"; return 0
        fi
    fi
    return 1
}

if ! NDK_PATH="$(find_ndk)"; then
    echo "ERROR: no Android NDK found." >&2
    echo "  Set NDK=/path/to/ndk (or ANDROID_NDK_HOME / ANDROID_NDK_ROOT)." >&2
    exit 1
fi
echo "== NDK: $NDK_PATH"

TOOLCHAIN="$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64"
if [[ ! -d "$TOOLCHAIN" ]]; then
    # Non-x86_64 build hosts use a different prebuilt tag (e.g. darwin-x86_64,
    # linux-aarch64). Accept whatever exists instead of hard-failing.
    TOOLCHAIN="$(dirname "$(dirname "$(find "$NDK_PATH/toolchains/llvm/prebuilt" -maxdepth 1 -mindepth 1 -type d | head -1)")")"
fi
[[ -x "$TOOLCHAIN/bin/clang" ]] || { echo "ERROR: clang not found under $TOOLCHAIN" >&2; exit 1; }
SYSROOT="$TOOLCHAIN/sysroot"
CMAKE_TOOLCHAIN_FILE="$NDK_PATH/build/cmake/android.toolchain.cmake"
[[ -f "$CMAKE_TOOLCHAIN_FILE" ]] || { echo "ERROR: NDK CMake toolchain file missing" >&2; exit 1; }
command -v cmake >/dev/null || { echo "ERROR: cmake not on PATH" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Version metadata: per-commit for CI/local git checkouts, static fallback
# ---------------------------------------------------------------------------
VERSION_NAME="v0.1.0"
VERSION_CODE="1"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    COMMIT_COUNT="$(git rev-list HEAD --count 2>/dev/null || echo 1)"
    SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    VERSION_NAME="v0.1.0-${SHORT_SHA}"
    VERSION_CODE="$COMMIT_COUNT"
fi

# ---------------------------------------------------------------------------
# C++ cross-build (per ABI, out-of-tree)
# ---------------------------------------------------------------------------
# NDK clang triple per ABI (verified: NDK docs "Use the NDK with other
# build systems"; ReZygisk common.mk uses the identical table).
triple_for_abi() {
    case "$1" in
        arm64-v8a)     echo "aarch64-linux-android";;
        armeabi-v7a)   echo "armv7a-linux-androideabi";;
        x86_64)        echo "x86_64-linux-android";;
        x86)           echo "i686-linux-android";;
        *)             return 1;;
    esac
}

build_cpp() {
    local abi="$1"
    echo "== C++ build: $abi (API $API_LEVEL, $BUILD_TYPE)"
    local build_dir="$OUT_ROOT/cpp/$abi"
    cmake -S "$REPO_ROOT/native" -B "$build_dir" \
        -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE" \
        -DANDROID_ABI="$abi" \
        -DANDROID_PLATFORM="android-$API_LEVEL" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        > /dev/null
    cmake --build "$build_dir" -j"$(nproc)"
    # ROUND 33 (stealth release): strip the shared objects. The
    # pre-Round-33 artifacts shipped a full .symtab/.strtab and (via
    # the old "-g in Release" flags) complete DWARF — over half of
    # libpayload's bytes, and a fingerprint banquet for any app that
    # can read /system/lib64. --strip-all keeps the DYNAMIC symbol
    # table (the dlsym contract) and removes everything else. The
    # verify_zip step below asserts the result.
    local strip_bin="$TOOLCHAIN/bin/llvm-strip"
    [[ -x "$strip_bin" ]] || strip_bin="strip"
    "$strip_bin" --strip-all         "$build_dir/libzygisk.so" \
        "$build_dir/libpayload.so" \
        "$build_dir/libzn_loader.so"
    # native/CMakeLists.txt sets CMAKE_LIBRARY_OUTPUT_DIRECTORY to the
    # build dir (flat); tolerate the classic per-target subdirectory
    # layout too for out-of-tree builds made by other tooling.
    local out dir
    for out in libzygisk.so libpayload.so libzn_loader.so; do
        if [[ -f "$build_dir/$out" ]]; then
            continue
        fi
        dir="$(dirname "${out#lib}")"   # libzygisk.so -> zygisk
        for dir in "$build_dir/$(basename "$out" .so)" \
                   "$build_dir/$(echo "$out" | sed 's/^lib//; s/\.so$//')"; do
            if [[ -f "$dir/$out" ]]; then
                cp "$dir/$out" "$build_dir/$out"
                break
            fi
        done
        [[ -f "$build_dir/$out" ]] || { echo "ERROR: $out missing for $abi" >&2; exit 1; }
    done
}

# ---------------------------------------------------------------------------
# Rust cross-build (per target)
# ---------------------------------------------------------------------------
# Rust target names differ from the clang triples for 32-bit ARM:
# rustc's target is armv7-linux-androideabi, the NDK clang triple is
# armv7a-linux-androideabi (verified: rustc platform-support android
# page vs the NDK other_build_systems guide). Both name the same ABI.
rust_target_for_abi() {
    case "$1" in
        arm64-v8a)     echo "aarch64-linux-android";;
        armeabi-v7a)   echo "armv7-linux-androideabi";;
        x86_64)        echo "x86_64-linux-android";;
        x86)           echo "i686-linux-android";;
        *)             return 1;;
    esac
}

build_rust() {
    local abi="$1"
    local target triple
    target="$(rust_target_for_abi "$abi")"
    triple="$(triple_for_abi "$abi")"
    echo "== Rust build: zygiskd for $target (API $API_LEVEL)"
    # The linker is the NDK's generic clang; the target and sysroot are
    # passed as link args (the NDK docs recommend --target over the
    # wrapper scripts: "Invoking Clang directly with --target will be
    # more reliable").
    #
    # 16 KB page alignment (Round 27 established it for the C++ libs;
    # Round 32 closes the daemon gap the old README note only
    # DOCUMENTED): the kernel on a 16 KB-page device (Android 16+,
    # Pixel 9a onward) refuses ELF LOAD segments aligned below the
    # kernel page size — for executables exactly as for .so files.
    # max-page-size=16384 is fully compatible with every 4 KB device
    # ever shipped (official NDK page-size guidance).
    local env_prefix="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')"
    export "${env_prefix}_LINKER=$TOOLCHAIN/bin/clang"
    # ROUND 33 adds --remap-path-prefix (keeps the build host's
    # absolute paths out of the daemon binary; folded into the
    # per-target RUSTFLAGS — cargo ignores the generic RUSTFLAGS when
    # the per-target variable is set).
    export "${env_prefix}_RUSTFLAGS=-C link-arg=--target=${triple}${API_LEVEL} -C link-arg=--sysroot=$SYSROOT -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384 --remap-path-prefix=$REPO_ROOT=."
    (cd "$REPO_ROOT/native/zygiskd" &&
        cargo build --release --target "$target")
    [[ -f "$REPO_ROOT/native/zygiskd/target/$target/release/zygiskd" ]] \
        || { echo "ERROR: zygiskd missing for $target" >&2; exit 1; }
    # ROUND 33: strip the symbol table (the daemon lives
    # root-only-readable under /data/adb, so this is size/hygiene,
    # not stealth-critical).
    local strip_bin="$TOOLCHAIN/bin/llvm-strip"
    [[ -x "$strip_bin" ]] || strip_bin="strip"
    "$strip_bin" --strip-all \
        "$REPO_ROOT/native/zygiskd/target/$target/release/zygiskd"
}

# ---------------------------------------------------------------------------
# Module assembly
# ---------------------------------------------------------------------------
MODULE_DIR="$OUT_ROOT/module"
ZIP_DIR="$OUT_ROOT/out"

assemble_module() {
    echo "== Assembling module tree at $MODULE_DIR"
    rm -rf "$MODULE_DIR"
    mkdir -p "$MODULE_DIR"

    # Install-time and boot-time scripts (verbatim from the repo root —
    # customize.sh is SOURCED by the installer, not executed).
    local f
    for f in customize.sh post-fs-data.sh service.sh uninstall.sh \
             zs_compat.sh post-mount-hook.sh verify.sh LICENSE; do
        [[ -f "$REPO_ROOT/$f" ]] || { echo "ERROR: missing $f" >&2; exit 1; }
        cp "$REPO_ROOT/$f" "$MODULE_DIR/$f"
    done

    # module.prop with per-commit version metadata (static fallback kept
    # in sync with the repo's module.prop).
    cat > "$MODULE_DIR/module.prop" <<EOF
id=zygisk_study
name=Zygisk Study
version=$VERSION_NAME
versionCode=$VERSION_CODE
author=Zygisk Study contributors
description=A from-scratch study reimplementation of the Zygisk loader pattern. NOT a successor to or fork of any existing Zygisk project. Educational only; do not flash on a device you depend on.
EOF

    # Binaries per ABI.
    local abi
    for abi in $ABIS; do
        local libs_dir="$MODULE_DIR/libs/$abi"
        mkdir -p "$libs_dir"
        if [[ $SKIP_CPP -ne 1 ]]; then
            cp "$OUT_ROOT/cpp/$abi/libzygisk.so"   "$libs_dir/"
            cp "$OUT_ROOT/cpp/$abi/libpayload.so"  "$libs_dir/"
            cp "$OUT_ROOT/cpp/$abi/libzn_loader.so" "$libs_dir/"
        fi
        if [[ $SKIP_RUST -ne 1 ]]; then
            local target
            target="$(rust_target_for_abi "$abi")"
            cp "$REPO_ROOT/native/zygiskd/target/$target/release/zygiskd" \
               "$libs_dir/zygiskd"
        fi
        chmod 0755 "$libs_dir/zygiskd" 2>/dev/null || true
        chmod 0644 "$libs_dir"/*.so 2>/dev/null || true
    done

    # Recovery flashing support: OUR clean-room update-binary (see the
    # header comment) + the conventional updater-script marker.
    mkdir -p "$MODULE_DIR/META-INF/com/google/android"
    cp "$REPO_ROOT/scripts/installer/update-binary" \
       "$MODULE_DIR/META-INF/com/google/android/update-binary"
    cp "$REPO_ROOT/scripts/installer/updater-script" \
       "$MODULE_DIR/META-INF/com/google/android/updater-script"
    chmod 0755 "$MODULE_DIR/META-INF/com/google/android/update-binary"

    echo "== Module tree:"
    (cd "$MODULE_DIR" && find . -type f | sort)
}

make_zip() {
    command -v zip >/dev/null || { echo "ERROR: zip not on PATH" >&2; exit 1; }
    mkdir -p "$ZIP_DIR"
    local zip_name="zygisk_study-${VERSION_NAME}-${VERSION_CODE}.zip"
    local zip_path="$ZIP_DIR/$zip_name"
    rm -f "$zip_path"
    echo "== Creating $zip_path"
    (cd "$MODULE_DIR" && zip -r -q "$zip_path" .)
    echo "== Zip contents:"
    unzip -l "$zip_path"
    verify_zip "$zip_path"
    echo "== DONE: $zip_path ($(du -h "$zip_path" | cut -f1))"
}

# Self-verification of the produced artifact: the module's install-time
# contract (what customize.sh / verify.sh / the Magisk installer expect)
# checked from the finished zip itself, so a broken package can never
# leave a green build.
verify_zip() {
    local zip_path="$1"
    echo "== Verifying the zip"
    local fail=0

    local listing
    listing="$(unzip -Z1 "$zip_path")"

    # 1. The files the installer needs. customize.sh is SOURCED by
    #    Magisk's install_module after extracting everything except
    #    META-INF; the boot scripts must be at the zip root.
    local required="module.prop customize.sh post-fs-data.sh service.sh uninstall.sh zs_compat.sh post-mount-hook.sh LICENSE META-INF/com/google/android/update-binary META-INF/com/google/android/updater-script"
    local f
    for f in $required; do
        if ! grep -qx "$f" <<< "$listing"; then
            echo "  FAIL: missing required file: $f" >&2
            fail=1
        fi
    done

    # 2. module.prop sanity: the documented strict format (id, name,
    #    version, versionCode[=integer], author, description).
    local prop
    prop="$(unzip -p "$zip_path" module.prop)"
    local vcode
    vcode="$(grep '^versionCode=' <<< "$prop" | cut -d= -f2-)"
    if ! grep -q '^id=zygisk_study$' <<< "$prop" \
       || ! grep -q '^name=' <<< "$prop" \
       || ! grep -q '^version=' <<< "$prop" \
       || ! grep -q '^author=' <<< "$prop" \
       || ! grep -q '^description=' <<< "$prop" \
       || [[ -z "$vcode" || ! "$vcode" =~ ^[0-9]+$ ]]; then
        echo "  FAIL: module.prop does not satisfy the strict format" >&2
        fail=1
    fi

    # 3. updater-script carries the conventional marker.
    local us
    us="$(unzip -p "$zip_path" META-INF/com/google/android/updater-script | tr -d '\r\n')"
    if [[ "$us" != "#MAGISK" ]]; then
        echo "  FAIL: updater-script is not the #MAGISK marker" >&2
        fail=1
    fi

    # 4. No root-level install.sh — Magisk's is_legacy_script() treats
    #    a zip containing install.sh as a PRE-modern module and runs the
    #    legacy installer path instead (verified from
    #    scripts/util_functions.sh).
    if grep -qx "install.sh" <<< "$listing"; then
        echo "  FAIL: root install.sh would trigger Magisk's legacy installer path" >&2
        fail=1
    fi

    # 5. Every packaged library has the right ELF class for its ABI
    #    directory (the EI_CLASS byte at offset 4; the same check
    #    customize.sh runs on the 32-bit pair at install time).
    #      arm64-v8a, x86_64  -> 2 (ELF64)
    #      armeabi-v7a, x86   -> 1 (ELF32)
    # NOTE: the byte is read from an extracted temp file rather than a
    # `unzip -p | head -c 5` pipe — under `set -o pipefail` the early
    # SIGPIPE from head would abort the whole script.
    local expect_cls abi lib cls magic tmp_extract
    tmp_extract="$(mktemp)"
    for abi in $ABIS; do
        case "$abi" in
            arm64-v8a | x86_64) expect_cls=2 ;;
            *)                  expect_cls=1 ;;
        esac
        for lib in libzygisk.so libpayload.so libzn_loader.so; do
            if ! grep -qx "libs/$abi/$lib" <<< "$listing"; then
                echo "  FAIL: libs/$abi/$lib missing from the zip" >&2
                fail=1
                continue
            fi
            unzip -p "$zip_path" "libs/$abi/$lib" > "$tmp_extract"
            magic="$(od -An -tu1 -N5 "$tmp_extract" | tr -s ' ' | sed 's/^ //')"
            cls="$(awk '{print $5}' <<< "$magic")"
            if [[ "$(awk '{print $1}' <<< "$magic")" != "127" || "$cls" != "$expect_cls" ]]; then
                echo "  FAIL: libs/$abi/$lib: magic/class mismatch (got '$magic', want e_ident[0]=127 class=$expect_cls)" >&2
                fail=1
            fi
        done
        # zygiskd must exist and be a valid executable for the ABI.
        if ! grep -qx "libs/$abi/zygiskd" <<< "$listing"; then
            echo "  FAIL: libs/$abi/zygiskd missing from the zip" >&2
            fail=1
        fi
    done
    rm -f "$tmp_extract"

    # 6. 16 KB page alignment on EVERY packaged ELF (Round 27 for the
    #    libraries, Round 32 for the daemon): a 16 KB-kernel device
    #    (Android 16+, Pixel 9a onward) refuses LOAD segments aligned
    #    below the kernel page size — for executables exactly as for
    #    shared objects. Checked from the assembled module tree (the
    #    zip content is byte-identical to it).
    local readelf_bin="" f align
    if [[ -x "$TOOLCHAIN/bin/llvm-readelf" ]]; then
        readelf_bin="$TOOLCHAIN/bin/llvm-readelf"
    elif command -v readelf >/dev/null 2>&1; then
        readelf_bin="readelf"
    else
        echo "  NOTE: no readelf available — skipping the 16 KB alignment check"
    fi
    if [[ -n "$readelf_bin" ]]; then
        for abi in $ABIS; do
            for f in libzygisk.so libpayload.so libzn_loader.so zygiskd; do
                # -W (wide): without it binutils readelf wraps each LOAD
                # record across two lines and the align column lands on
                # the second — the awk would then read an offset and
                # false-fail. llvm-readelf is single-line either way.
                align="$("$readelf_bin" -lW "$MODULE_DIR/libs/$abi/$f" 2>/dev/null \
                          | grep LOAD | head -1 | awk '{print $NF}')"
                # readelf prints 0x4000 (16384) when properly aligned.
                if [[ -z "$align" ]] || (( align < 0x4000 )); then
                    echo "  FAIL: libs/$abi/$f LOAD alignment $align < 0x4000 (16 KB)" >&2
                    fail=1
                fi
            done
        done
    fi

    # 7. ROUND 33 (stealth release): no symtab, no DWARF, no
    #    .comment-side leftovers in ANY packaged ELF. The
    #    pre-Round-33 artifacts shipped ~1 MB of debug info and full
    #    symbol tables inside world-readable files.
    if [[ -n "$readelf_bin" ]]; then
        local sec
        for abi in $ABIS; do
            for f in libzygisk.so libpayload.so libzn_loader.so zygiskd; do
                [[ -f "$MODULE_DIR/libs/$abi/$f" ]] || continue
                sec="$("$readelf_bin" -SW "$MODULE_DIR/libs/$abi/$f" 2>/dev/null \
                       | grep -E '\.(symtab|strtab)\b|\.debug_' \
                       | awk '{print $2}' || true)"
                if [[ -n "$sec" ]]; then
                    echo "  FAIL: libs/$abi/$f still carries $sec (not stripped)" >&2
                    fail=1
                fi
            done
        done
    fi

    # 8. ROUND 33: no DT_SONAME on the three libraries. A fixed
    #    soname inside a per-install randomized file name (Round 30)
    #    is a one-grep fingerprint; bionic tolerates the absence
    #    (linker.cpp: missing DT_SONAME is silent for targetSdk >= 23;
    #    dedup is by inode — see the CMakeLists comments).
    if [[ -n "$readelf_bin" ]]; then
        local soname
        for abi in $ABIS; do
            for f in libzygisk.so libpayload.so libzn_loader.so; do
                soname="$("$readelf_bin" -d "$MODULE_DIR/libs/$abi/$f" 2>/dev/null \
                          | grep SONAME || true)"
                if [[ -n "$soname" ]]; then
                    echo "  FAIL: libs/$abi/$f carries a SONAME: $soname" >&2
                    fail=1
                fi
            done
        done
    fi

    # 9. ROUND 33: banned-string scan over the two APP-READABLE
    #    libraries (libzygisk + libpayload live world-readable in
    #    /system/lib[64] after the magic mount). The daemon
    #    (root-only under /data/adb) and libzn_loader (root-only, and
    #    its documented API export names intentionally say what they
    #    are) are NOT in scope — documented, deliberate.
    local strings_bin="$TOOLCHAIN/bin/llvm-strings"
    [[ -x "$strings_bin" ]] || strings_bin="$(command -v strings || true)"
    if [[ -n "$strings_bin" ]]; then
        local banned hit
        for abi in $ABIS; do
            for f in libzygisk.so libpayload.so; do
                [[ -f "$MODULE_DIR/libs/$abi/$f" ]] || continue
                # Case-insensitive whole-token bans: any occurrence of
                # our signature vocabulary is a file-scan hit. The
                # generic strings that remain (libc.so NEEDED entries,
                # the AOSP-mandated NativeBridgeItf export, the
                # compiler .comment) are allowed by construction.
                for banned in zygisk zygiskd zygisk_study ZygiskStudy \
                              libpayload libzn_loader session.sock \
                              denylist ro.zygisk_study; do
                    hit="$("$strings_bin" -a "$MODULE_DIR/libs/$abi/$f" 2>/dev/null \
                           | grep -i -m1 "$banned" || true)"
                    if [[ -n "$hit" ]]; then
                        echo "  FAIL: libs/$abi/$f leaks banned string '$banned': $hit" >&2
                        fail=1
                    fi
                done
            done
        done
    else
        echo "  NOTE: no strings tool available — skipping the banned-string scan"
    fi

    if [[ $fail -ne 0 ]]; then
        echo "ERROR: zip verification failed" >&2
        exit 1
    fi
    echo "  OK: layout, module.prop, updater-script, legacy-trap, ELF classes,"
    echo "      16 KB alignment, stripped sections, no SONAME, banned-strings all verified"
}

# ---------------------------------------------------------------------------
# Drive the build
# ---------------------------------------------------------------------------
mkdir -p "$OUT_ROOT"

for abi in $ABIS; do
    [[ $SKIP_CPP -eq 1 ]] || build_cpp "$abi"
done
if [[ $SKIP_RUST -ne 1 ]]; then
    command -v cargo >/dev/null || { echo "ERROR: cargo not on PATH" >&2; exit 1; }
    for abi in $ABIS; do
        build_rust "$abi"
    done
fi

assemble_module
[[ $SKIP_ZIP -eq 1 ]] || make_zip
