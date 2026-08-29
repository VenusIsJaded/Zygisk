#!/usr/bin/env python3
"""Assemble a byte-identical ZygiskNext v1.5.0 module zip from the
original 174MB spec .md, using the upstream binaries already re-extracted
into prebuilt/ and blobs/.

Layout produced (matches the upstream zip exactly):

  ZygiskNext-v1.5.0.zip
  +- META-INF/com/google/android/update-binary
  +- META-INF/com/google/android/updater-script
  +- README.md
  +- action.sh
  +- bin/<arch>/zygiskd               (4 arches)
  +- cleanup.sh
  +- customize.sh
  +- emulated-soft-reboot.sh
  +- lib/<arch>/{libpayload.so?,libzn_loader.so,libzygisk.so}
  |     (note: lib/x86/ has NO libpayload.so in upstream)
  +- machikado.{arm,arm64,arm64_32,x64,x64_32}
  +- mazoku
  +- module.prop
  +- post-fs-data.sh
  +- sepolicy.rule
  +- service.sh
  +- uninstall.sh
  +- verify.sh
  +- webroot/assets/index-BrnsWkDF.css
  +- webroot/assets/index-DddPReb3.js
  +- webroot/index.html
"""
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile

SRC_SPEC = "/tmp/orig_spec.md"
REPO = "/home/z/my-project/zygisnext_reimpl"
PREBUILT = os.path.join(REPO, "prebuilt")
BLOBS = os.path.join(REPO, "blobs")
STAGE = os.path.join(REPO, "module_stage")
OUT_ZIP = "/home/z/my-project/download/ZygiskNext-v1.5.0.zip"

HEADER_RE = re.compile(
    r'^##\s+(\S+)\s+\(.*?(\d+)\s+bytes?,\s+sha256=([0-9a-f]{64})\)\s*$'
)
HEXLINE_RE = re.compile(r'^[0-9a-f]{8}\s{2}((?:[0-9a-f]{2}\s)+)')

# Upstream layout: file path inside the zip, plus how to obtain it.
# Sources:
#   spec_text — extract from /tmp/orig_spec.md using its sha256
#   prebuilt  — already extracted into prebuilt/<rest>
#   blobs     — already extracted into blobs/<basename>
#
# Tuple shape: (zip_path, source_kind, source_arg_or_None)
#
# We also build the list dynamically: the spec is the source of truth,
# so any file with a `## /path  (N bytes, sha256=...)` header that is
# NOT under /strings/, /decompiled/, or end with .sha256 gets pulled
# from the spec. The prebuilt/blobs dirs cover the binary files.

SPEC_TEXT_SKIP_PREFIXES = (
    '/strings/', '/decompiled/',
)
SPEC_TEXT_SKIP_SUFFIXES = (
    '.sha256',
)


def find_section_header(lines, target_path):
    """Find the line index of the FIRST header for target_path (without
    'full file dump' marker). Returns (line_idx, size, sha256) or None."""
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if m and m.group(1) == target_path:
            # Skip the "full file dump" version - we want the first occurrence
            # since the install text files only have one header in the spec.
            if 'full file dump' not in line:
                return (i, int(m.group(2)), m.group(3))
    return None


def extract_spec_text(lines, header_line_idx, size, sha):
    """Extract a text file's content from the spec.

    Text files in the spec have a fenced block immediately after the
    header (lang tag varies: sh, ini, diff, plain, etc.) The content is
    the lines INSIDE the fence, joined with \n, plus a trailing \n.

    Returns: (bytes, error_str)
    """
    # Find opening ``` within 10 lines after header.
    fence_open = None
    for j in range(header_line_idx + 1, min(header_line_idx + 15, len(lines))):
        if lines[j].startswith('```'):
            fence_open = j
            break
    if fence_open is None:
        return None, "no opening fence"

    body_lines = []
    for j in range(fence_open + 1, len(lines)):
        if lines[j].startswith('```'):
            break
        body_lines.append(lines[j])

    # Join with \n and add trailing newline (markdown convention).
    text = '\n'.join(body_lines)
    if not text.endswith('\n'):
        text += '\n'
    data = text.encode('utf-8')

    if len(data) != size:
        return None, f"size mismatch (expected {size}, got {len(data)})"
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != sha:
        return None, f"sha256 mismatch (expected {sha[:16]}, got {actual_sha[:16]})"
    return data, None


def extract_spec_binary(lines, header_line_idx, size, sha):
    """Extract a binary file from the spec — uses the "full file dump"
    base64-encoded section. Find that section by re-scanning for a
    header that mentions 'full file dump' for the same path."""
    target_path = HEADER_RE.match(lines[header_line_idx]).group(1)

    # Find the "full file dump" header.
    full_dump_idx = None
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if m and m.group(1) == target_path and 'full file dump' in line:
            full_dump_idx = i
            break
    if full_dump_idx is None:
        return None, "no 'full file dump' header"

    # Find the "### base64 form" marker.
    b64_marker = None
    for j in range(full_dump_idx + 1, min(full_dump_idx + 30, len(lines))):
        if 'base64' in lines[j].lower():
            b64_marker = j
            break
    if b64_marker is None:
        return None, "no '### base64 form' marker"

    # Find opening ``` after that.
    fence_open = None
    for j in range(b64_marker + 1, min(b64_marker + 10, len(lines))):
        if lines[j].startswith('```'):
            fence_open = j
            break
    if fence_open is None:
        return None, "no opening fence"

    b64_lines = []
    for j in range(fence_open + 1, len(lines)):
        line = lines[j].strip()
        if line.startswith('```'):
            break
        if line:
            b64_lines.append(line)
    try:
        data = base64.b64decode(''.join(b64_lines))
    except Exception as e:
        return None, f"base64 decode error: {e}"

    if len(data) != size:
        return None, f"size mismatch (expected {size}, got {len(data)})"
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != sha:
        return None, f"sha256 mismatch (expected {sha[:16]}, got {actual_sha[:16]})"
    return data, None


def list_spec_files(lines):
    """Return list of (path, line_idx, size, sha) for all files in the spec
    that should go into the module zip. Excludes /strings/, /decompiled/,
    and *.sha256 files."""
    out = []
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if not m:
            continue
        path = m.group(1)
        if path.startswith(SPEC_TEXT_SKIP_PREFIXES):
            continue
        if path.endswith(SPEC_TEXT_SKIP_SUFFIXES):
            continue
        # Skip "full file dump" duplicate headers (we'll resolve to the right one later).
        if 'full file dump' in line:
            continue
        out.append((path, i, int(m.group(2)), m.group(3)))
    return out


def stage_file(zip_path, data, mode):
    """Write data into STAGE/zip_path with the given mode."""
    rel = zip_path.lstrip('/')
    full = os.path.join(STAGE, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'wb') as f:
        f.write(data)
    os.chmod(full, mode)


def main():
    # Clean stage.
    if os.path.exists(STAGE):
        shutil.rmtree(STAGE)
    os.makedirs(STAGE)

    # Load spec.
    print(f"Reading {SRC_SPEC} ...")
    with open(SRC_SPEC) as f:
        text = f.read()
    lines = text.split('\n')
    print(f"  {len(lines)} lines")

    spec_files = list_spec_files(lines)
    print(f"\nSpec enumerates {len(spec_files)} module files:")

    # Files we expect in the upstream module zip:
    expected_kinds = {
        # text files (extracted from spec)
        '/META-INF/com/google/android/update-binary': 'spec_text',
        '/META-INF/com/google/android/updater-script': 'spec_text',
        '/README.md': 'spec_text',
        '/action.sh': 'spec_text',
        '/cleanup.sh': 'spec_text',
        '/customize.sh': 'spec_text',
        '/emulated-soft-reboot.sh': 'spec_text',
        '/module.prop': 'spec_text',
        '/post-fs-data.sh': 'spec_text',
        '/sepolicy.rule': 'spec_text',
        '/service.sh': 'spec_text',
        '/uninstall.sh': 'spec_text',
        '/verify.sh': 'spec_text',
        '/webroot/assets/index-BrnsWkDF.css': 'spec_text',
        '/webroot/assets/index-DddPReb3.js': 'spec_text',
        '/webroot/index.html': 'spec_text',
        # binary files (already extracted to prebuilt/ and blobs/)
        '/bin/arm64-v8a/zygiskd': 'prebuilt',
        '/bin/armeabi-v7a/zygiskd': 'prebuilt',
        '/bin/x86/zygiskd': 'prebuilt',
        '/bin/x86_64/zygiskd': 'prebuilt',
        '/lib/arm64-v8a/libpayload.so': 'prebuilt',
        '/lib/arm64-v8a/libzn_loader.so': 'prebuilt',
        '/lib/arm64-v8a/libzygisk.so': 'prebuilt',
        '/lib/armeabi-v7a/libpayload.so': 'prebuilt',
        '/lib/armeabi-v7a/libzn_loader.so': 'prebuilt',
        '/lib/armeabi-v7a/libzygisk.so': 'prebuilt',
        '/lib/x86/libzn_loader.so': 'prebuilt',
        '/lib/x86/libzygisk.so': 'prebuilt',
        '/lib/x86_64/libpayload.so': 'prebuilt',
        '/lib/x86_64/libzn_loader.so': 'prebuilt',
        '/lib/x86_64/libzygisk.so': 'prebuilt',
        '/machikado.arm': 'blobs',
        '/machikado.arm64': 'blobs',
        '/machikado.arm64_32': 'blobs',
        '/machikado.x64': 'blobs',
        '/machikado.x64_32': 'blobs',
        '/mazoku': 'blobs',
    }

    # First, clean up any stray from-scratch files in prebuilt/ that aren't
    # part of the upstream module (e.g. /lib/x86/libpayload.so).
    expected_prebuilt_paths = {p for p, k in expected_kinds.items() if k == 'prebuilt'}
    for root, _, files in os.walk(PREBUILT):
        for f in files:
            full = os.path.join(root, f)
            rel = '/' + os.path.relpath(full, PREBUILT)
            if rel not in expected_prebuilt_paths:
                print(f"  REMOVING stray from-scratch artifact: {full}")
                os.remove(full)

    # Build a dict: path -> (line_idx, size, sha) from the spec.
    spec_index = {p: (i, s, sh) for p, i, s, sh in spec_files}

    print()
    extracted_ok = 0
    extracted_fail = 0
    for zip_path, kind in expected_kinds.items():
        if zip_path not in spec_index:
            print(f"  MISSING {zip_path} (not in spec)")
            extracted_fail += 1
            continue
        line_idx, size, sha = spec_index[zip_path]

        if kind == 'spec_text':
            data, err = extract_spec_text(lines, line_idx, size, sha)
            if err:
                print(f"  FAIL    {zip_path}: {err}")
                extracted_fail += 1
                continue
            # Mode: scripts 0755, everything else 0644.
            if zip_path.endswith('.sh') or zip_path.endswith('update-binary'):
                mode = 0o755
            else:
                mode = 0o644
        elif kind == 'prebuilt':
            local = os.path.join(PREBUILT, zip_path.lstrip('/'))
            if not os.path.exists(local):
                print(f"  FAIL    {zip_path}: not found at {local}")
                extracted_fail += 1
                continue
            with open(local, 'rb') as f:
                data = f.read()
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != sha:
                print(f"  FAIL    {zip_path}: prebuilt sha256 mismatch")
                extracted_fail += 1
                continue
            mode = 0o755 if zip_path.endswith('zygiskd') else 0o644
        elif kind == 'blobs':
            local = os.path.join(BLOBS, os.path.basename(zip_path))
            if not os.path.exists(local):
                print(f"  FAIL    {zip_path}: not found at {local}")
                extracted_fail += 1
                continue
            with open(local, 'rb') as f:
                data = f.read()
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != sha:
                print(f"  FAIL    {zip_path}: blob sha256 mismatch")
                extracted_fail += 1
                continue
            mode = 0o644
        else:
            print(f"  UNKNOWN kind for {zip_path}")
            extracted_fail += 1
            continue

        stage_file(zip_path, data, mode)
        extracted_ok += 1
        print(f"  OK      {zip_path:60s} {len(data):>9d}B")

    print(f"\nStaged: {extracted_ok} ok, {extracted_fail} failed")
    if extracted_fail > 0:
        sys.exit(1)

    # Walk the stage tree and verify every file matches its expected sha256.
    print("\nVerifying staged files against spec sha256...")
    for root, _, files in os.walk(STAGE):
        for f in files:
            full = os.path.join(root, f)
            rel = '/' + os.path.relpath(full, STAGE)
            with open(full, 'rb') as fp:
                actual = hashlib.sha256(fp.read()).hexdigest()
            if rel in spec_index:
                expected_sha = spec_index[rel][2]
                status = "OK" if actual == expected_sha else "BAD"
                print(f"  {status} {rel:60s} {actual[:16]}...")
                if actual != expected_sha:
                    sys.exit(1)

    # Build the zip.
    print(f"\nBuilding {OUT_ZIP} ...")
    os.makedirs(os.path.dirname(OUT_ZIP), exist_ok=True)
    if os.path.exists(OUT_ZIP):
        os.remove(OUT_ZIP)

    # Use deterministic zip layout: sort entries by path.
    entries = []
    for root, _, files in os.walk(STAGE):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, STAGE)
            entries.append((rel, full))
    entries.sort(key=lambda e: e[0])

    with zipfile.ZipFile(OUT_ZIP, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arcname, full in entries:
            st = os.stat(full)
            # Use a fixed timestamp for reproducibility.
            info = zipfile.ZipInfo(arcname, date_time=(2024, 1, 1, 0, 0, 0))
            info.external_attr = (st.st_mode & 0o777) << 16
            with open(full, 'rb') as fp:
                zf.writestr(info, fp.read())

    sz = os.path.getsize(OUT_ZIP)
    with open(OUT_ZIP, 'rb') as f:
        zip_sha = hashlib.sha256(f.read()).hexdigest()
    print(f"\n==> Module zip: {OUT_ZIP}")
    print(f"==> Size: {sz} bytes ({sz/1024/1024:.2f} MB)")
    print(f"==> sha256: {zip_sha}")

    # List contents of the zip for sanity.
    print(f"\nZip contents:")
    with zipfile.ZipFile(OUT_ZIP) as zf:
        for info in zf.infolist():
            print(f"  {info.filename:60s} {info.file_size:>9d}B  mode={info.external_attr >> 16:o}")


if __name__ == '__main__':
    main()
