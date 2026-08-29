#!/usr/bin/env python3
"""Extract the binary files (.so, zygiskd, machikado/mazoku blobs)
from the original 174MB spec .md and place them in prebuilt/ and blobs/.

The original .md has two formats for binary content:
1. Small files (96-byte machikado/mazoku): inline hex dump format
   like `00000000  7b 62 93 31 ...   {b.1....`
2. Large files (zygiskd, lib*.so): a separate "full file dump"
   section with `### base64 form` followed by base64-encoded content

This script handles both. It also verifies SHA256 against the
documented checksums.
"""
import base64
import hashlib
import os
import re
import sys

SRC = "/tmp/orig_spec.md"
DST_ROOT = "/home/z/my-project/zygisnext_reimpl"

# Match: ## /path/to/file  (N bytes, sha256=hexdigest)
# OR:    ## /path/to/file  (full file dump, N bytes, sha256=hexdigest)
HEADER_RE = re.compile(
    r'^##\s+(\S+)\s+\(.*?(\d+)\s+bytes?,\s+sha256=([0-9a-f]{64})\)\s*$'
)

# Match a hex dump line: "00000000  7b 62 93 31 ...   {b.1...."
HEXLINE_RE = re.compile(r'^[0-9a-f]{8}\s{2}((?:[0-9a-f]{2}\s)+)')


def find_section_line(text_lines, target_header_substring, start=0):
    """Find the line index of a section header containing target."""
    for i in range(start, len(text_lines)):
        if target_header_substring in text_lines[i]:
            return i
    return -1


def extract_base64_block(text_lines, header_line_idx):
    """Given a '## /path  (full file dump, ...)' header line,
    find the ```-fenced base64 block and return decoded bytes.
    """
    # Find next "### base64 form" within 20 lines
    b64_marker = None
    for j in range(header_line_idx + 1, min(header_line_idx + 30, len(text_lines))):
        if 'base64' in text_lines[j].lower():
            b64_marker = j
            break
    if b64_marker is None:
        return None, "no '### base64 form' marker"

    # Find opening ``` after that
    fence_open = None
    for j in range(b64_marker + 1, min(b64_marker + 10, len(text_lines))):
        if text_lines[j].startswith('```'):
            fence_open = j
            break
    if fence_open is None:
        return None, "no opening fence"

    # Collect base64 lines until closing ```
    b64_lines = []
    for j in range(fence_open + 1, len(text_lines)):
        line = text_lines[j].strip()
        if line.startswith('```'):
            break
        if line:
            b64_lines.append(line)

    try:
        b64_str = ''.join(b64_lines)
        return base64.b64decode(b64_str), None
    except Exception as e:
        return None, f"base64 decode error: {e}"


def extract_hex_block(text_lines, header_line_idx):
    """Given a '## /path  (N bytes, sha256=...)' header line,
    find the ```-fenced hex dump and return decoded bytes.
    """
    # Find opening ``` within 10 lines
    fence_open = None
    for j in range(header_line_idx + 1, min(header_line_idx + 10, len(text_lines))):
        if text_lines[j].startswith('```'):
            fence_open = j
            break
    if fence_open is None:
        return None, "no opening fence"

    # Collect hex bytes until closing ```
    out = bytearray()
    for j in range(fence_open + 1, len(text_lines)):
        line = text_lines[j]
        if line.startswith('```'):
            break
        m = HEXLINE_RE.match(line)
        if m:
            hex_group = m.group(1)
            for byte_str in hex_group.split():
                out.append(int(byte_str, 16))
    return bytes(out), None


def map_path_to_local(upstream_path):
    """Map /bin/<abi>/zygiskd and /lib/<abi>/lib*.so to local prebuilt paths.
    Map /machikado.* and /mazoku to blobs/."""
    if upstream_path.startswith('/bin/'):
        # /bin/arm64-v8a/zygiskd  →  prebuilt/bin/arm64-v8a/zygiskd
        return os.path.join(DST_ROOT, 'prebuilt', upstream_path.lstrip('/'))
    if upstream_path.startswith('/lib/'):
        return os.path.join(DST_ROOT, 'prebuilt', upstream_path.lstrip('/'))
    if upstream_path.startswith('/machikado') or upstream_path == '/mazoku':
        return os.path.join(DST_ROOT, 'blobs', os.path.basename(upstream_path))
    return None


def main():
    print(f"Reading {SRC} ...")
    with open(SRC) as f:
        text = f.read()
    lines = text.split('\n')
    print(f"  {len(lines)} lines")

    # Find all section headers matching HEADER_RE.
    sections = []
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if m:
            path = m.group(1)
            size = int(m.group(2))
            sha = m.group(3)
            sections.append((i, path, size, sha))
    print(f"Found {len(sections)} binary section headers")

    # Filter to only the binary files we care about
    # (zygiskd, lib*.so, machikado.*, mazoku).
    wanted_prefixes = ('/bin/', '/lib/', '/machikado', '/mazoku')
    wanted = [s for s in sections if s[1].startswith(wanted_prefixes)]
    print(f"Wanted binary files: {len(wanted)}")

    # For paths that appear twice (first as descriptive header, then as
    # "full file dump" header), prefer the "full file dump" version
    # because it has the actual content. Build a dict: path -> list of
    # (line, size, sha, is_full_dump)
    by_path = {}
    for sec in wanted:
        line_idx, path, size, sha = sec
        header_text = lines[line_idx]
        is_full_dump = 'full file dump' in header_text
        by_path.setdefault(path, []).append((line_idx, size, sha, is_full_dump))

    # For each path, pick the best section: prefer is_full_dump=True
    # (used for large files), fall back to the inline version (used
    # for 96-byte blobs).
    chosen = []
    for path, occurrences in by_path.items():
        # Prefer the full-file-dump occurrence
        full_dump = [o for o in occurrences if o[3]]
        if full_dump:
            line_idx, size, sha, _ = full_dump[0]
            chosen.append((path, line_idx, size, sha, 'base64'))
        else:
            line_idx, size, sha, _ = occurrences[0]
            chosen.append((path, line_idx, size, sha, 'hex'))

    print(f"\nExtracting {len(chosen)} binaries:")
    extracted = 0
    failed = 0
    for path, line_idx, size, sha, fmt in chosen:
        local_path = map_path_to_local(path)
        if local_path is None:
            print(f"  SKIP  {path} (no local mapping)")
            continue

        if fmt == 'base64':
            data, err = extract_base64_block(lines, line_idx)
        else:
            data, err = extract_hex_block(lines, line_idx)

        if err:
            print(f"  FAIL  {path}: {err}")
            failed += 1
            continue

        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != sha:
            print(f"  BAD   {path}: sha256 mismatch (expected {sha[:16]}..., got {actual_sha[:16]}...)")
            failed += 1
            continue

        if len(data) != size:
            print(f"  BAD   {path}: size mismatch (expected {size}, got {len(data)})")
            failed += 1
            continue

        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, 'wb') as f:
            f.write(data)
        extracted += 1
        rel = os.path.relpath(local_path, DST_ROOT)
        print(f"  OK    {rel:50s}  {len(data):>9d}B  sha256={actual_sha[:16]}...")

    print(f"\nExtracted: {extracted}, failed: {failed}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
