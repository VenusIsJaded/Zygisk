#!/usr/bin/env python3
# machikado/mazoku blob generator
#
# These 6 files are 96-byte binary blobs shipped with Zygisk Next
# v1.5.0. They are loaded by zygiskd at startup, but zygiskd does
# not mention their filenames as plaintext strings — meaning the
# filenames are stored encrypted in zygiskd's .rodata and decrypted
# at runtime (see Section 12 of the spec for the known-gap note
# about runtime-decrypted strings).
#
# Structural analysis (observable from the bytes alone):
#
#   1. machikado.{arm,arm64,arm64_32,x64,x64_32} all share the
#      same trailing 32-byte block:
#          b5 56 07 60 d3 b5 be 4d 6b 36 0e 5a 14 0f a2 15
#          cf da 1e bd b7 a1 99 bb 25 4d 5b 96 80 15 e4 57
#      This is consistent with a fixed 32-byte signature/MAC
#      appended to a per-arch 64-byte payload.
#
#   2. mazoku has its own 96 bytes with no shared suffix with the
#      machikado family. It's probably a different kind of blob
#      (a per-instance key, a master config, or a different
#      signature scheme).
#
#   3. The first 64 bytes of each machikado.* file are unique and
#      high-entropy — consistent with encrypted content (the
#      decryption key would be inside zygiskd's binary, recovered
#      only by reading the decompiled code).
#
# What these blobs actually contain:
#   I do not know. Determining their semantic purpose would
#   require reading zygiskd's decompiled C pseudocode (Section 7
#   of the spec) to find where they're opened and parsed. That's
#   explicitly out-of-scope for this from-scratch reimplementation.
#
# What this script does:
#   Reconstructs the 6 blobs byte-for-byte from their hex dumps.
#   Verifies SHA256 against the documented checksums. The output
#   is identical to the original — this is just a readable form
#   of the same data.

import argparse
import hashlib
import os
import sys

# Each blob: (name, sha256_hex, full_hex_bytes)
# Hex strings are split into 64-char (32-byte) lines for
# readability. Python concatenates adjacent string literals.
BLOBS = [
    ("machikado.arm",
     "e8b7ab133dfb5d471577c24af3c091e562a9f760620d7a9954cb4ad582299917",
     "7b629331f10dc3d321b804294a4fcca7abba77ceed1b0577f72588aff8562668"
     "a2c9aa00e8786db397e3edf0f56948eb39f5408536d865de12effb91a6977306"
     "b5560760d3b5be4d6b360e5a140fa215cfda1ebdb7a199bb254d5b968015e457"),

    ("machikado.arm64",
     "99785d735bb20ffb152cdcde68d64a302c84c8030536880f44db502dfa1a3c82",
     "de4b0b2acd6a94807a1c39632b2f365dbc97d6ec0faf4092e2912080dfc398f1"
     "01d76f25302dec6ee8b24f9945e700efe438a545534857dcd5f8ebef0afcc90d"
     "b5560760d3b5be4d6b360e5a140fa215cfda1ebdb7a199bb254d5b968015e457"),

    ("machikado.arm64_32",
     "f7ca345daf1df121923c3a0c7c28165bb4bfa33332eaff3c18afc2b501ee8a36",
     "2f653a09e5e9e86f8f4ea7e38f1d0daacab57156d9d7a1d9cd17ee69997cb9fb"
     "449bd38a57cffca61dc3aac2cb14847677cf035b604d51dee932f2aa6082fb08"
     "b5560760d3b5be4d6b360e5a140fa215cfda1ebdb7a199bb254d5b968015e457"),

    ("machikado.x64",
     "e5d538cc763e31c8d5dceed917fb45dd8700711b3852aad9e169715f149fe88a",
     "1341c1f5f11a1ef1c82bf1fed6665d16ccd637716d60a1a6bcd7bc3966040045"
     "8415535d4c439a5bc4ba5ace83e4de91eb0d2b5afbe9fe62999beb2bf7599309"
     "b5560760d3b5be4d6b360e5a140fa215cfda1ebdb7a199bb254d5b968015e457"),

    ("machikado.x64_32",
     "732ec98a1eca30ce7776d48cc7288cd60c2ea987a454e5b640b2d7f70f7fb7ac",
     "1f8d5d925f68940d5f4642d9d98fac9fb70a4b495e7cc2cf539db147af958a42"
     "a4311dedaa343bd24479860ee9a6096980611cc3bc8a1c1b549de2290cbf7004"
     "b5560760d3b5be4d6b360e5a140fa215cfda1ebdb7a199bb254d5b968015e457"),

    ("mazoku",
     "3b2dad985544742ef05d8061c3471a735f15dac6a0cd9356027936d15d5aeb98",
     "639784885d9c9120845b1f7bdaad16118242d275de353dd9724555d5105a84ca"
     "bfe8e33ca635df5f046ff1e3014de9124c956c95a2db5123fff89c43be7df90c"
     "20658fe4666a101517d9822fa937b311878e28e2b4673c62fe526707db6db164"),
]


def main():
    p = argparse.ArgumentParser(
        description="Reconstruct the 6 machikado/mazoku blobs"
                    " from their hex dumps.")
    p.add_argument("--out", default=".",
                  help="output directory for the 6 blob files")
    p.add_argument("--print-hex", action="store_true",
                  help="print hex dumps to stdout instead of writing")
    args = p.parse_args()

    all_ok = True
    for name, sha_hex, hex_bytes in BLOBS:
        # Strip any whitespace and concat.
        clean = "".join(hex_bytes.split())
        try:
            data = bytes.fromhex(clean)
        except ValueError as e:
            print(f"  BAD  {name}: hex parse error: {e}", file=sys.stderr)
            all_ok = False
            continue

        if len(data) != 96:
            print(f"  BAD  {name}: expected 96 bytes, got {len(data)}",
                  file=sys.stderr)
            all_ok = False
            continue

        if args.print_hex:
            print(f"=== {name} ({len(data)} bytes) ===")
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                print("  " + " ".join(f"{b:02x}" for b in chunk))
            print()
            continue

        path = os.path.join(args.out, name)
        with open(path, "wb") as f:
            f.write(data)
        actual = hashlib.sha256(data).hexdigest()
        ok = (actual == sha_hex)
        if not ok:
            all_ok = False
        mark = "OK" if ok else "BAD"
        print(f"  [{mark}] {name:25s} {len(data):>3d}B  sha256={actual}")

    if not all_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
