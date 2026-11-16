#!/usr/bin/env python3
"""Experimental, fail-closed single-instruction YTLite controller-creation guard.

Usage:
    python3 scripts/patch_ytlite_quality_init.py source.ipa patched.ipa

Only supports the exact YTLite 6.0 dylib identified by UUID
4294bd0c-2755-34f7-8405-003d18893302.

It replaces YTLite +0x3DC0C (a call that allocates
YTVideoQualitySwitchRedesignedController) with `mov x0, xzr`.
Consequently the subsequent ObjC init message goes to nil, returns nil,
and YTLite's `setRedesignedController:` receives nil.

This disables the invalid-controller creation; it does NOT supply the
missing service registry scope. It may affect the redesigned quality menu.
Only run on a throwaway copy of the IPA and sign it after this modification.
"""
from __future__ import annotations

import argparse
import re
import shutil
import struct
import sys
import uuid
import zipfile
from pathlib import Path

EXPECTED_UUID = uuid.UUID('4294bd0c-2755-34f7-8405-003d18893302')
PATCH_OFFSET = 0x3DC0C
# bl 0x40004 -> mov x0, xzr (no allocation; init sends message to nil)
BEFORE = bytes.fromhex('fe 08 00 94')
AFTER = bytes.fromhex('e0 03 1f aa')
# Verify the surrounding code still sends nil scope and parent to the
# Objective-C initializer and forwards its result to a setter.
CONTEXT = {
    0x3DC08: bytes.fromhex('0a 9b 5d 94'),
    0x3DC18: bytes.fromhex('02 00 80 d2'),
    0x3DC1C: bytes.fromhex('03 00 80 d2'),
    0x3DC20: bytes.fromhex('01 09 00 94'),
    0x3DC24: bytes.fromhex('f7 03 00 aa'),
    0x3DC38: bytes.fromhex('03 09 00 94'),
}
TARGET_PATTERN = re.compile(r'Payload/[^/]+\.app/Frameworks/YTLite\.dylib\Z')


def macho_uuid(data: bytes) -> uuid.UUID:
    if len(data) < 32:
        raise ValueError('YTLite binary is too short to contain a Mach-O header')
    magic, cpu_type, _, file_type, ncmds, sizeofcmds, _, _ = struct.unpack_from('<IiiIIIII', data, 0)
    if magic != 0xFEEDFACF or cpu_type != 0x0100000C or file_type != 6:
        raise ValueError('YTLite is not the expected ARM64 Mach-O dylib')
    end = 32 + sizeofcmds
    if end > len(data) or ncmds > 10000:
        raise ValueError('Invalid Mach-O load commands')
    pos = 32
    for _ in range(ncmds):
        if pos + 8 > end:
            raise ValueError('Truncated Mach-O load command')
        cmd, length = struct.unpack_from('<II', data, pos)
        if length < 8 or pos + length > end:
            raise ValueError('Invalid Mach-O load command size')
        if cmd == 0x1B:  # LC_UUID
            if length != 24:
                raise ValueError('Invalid Mach-O LC_UUID')
            return uuid.UUID(bytes=bytes(data[pos + 8:pos + 24]))
        pos += length
    raise ValueError('Missing Mach-O LC_UUID')


def patch_binary(original: bytes) -> bytes:
    actual_uuid = macho_uuid(original)
    if actual_uuid != EXPECTED_UUID:
        raise ValueError(f'Wrong YTLite UUID: {actual_uuid} (expected {EXPECTED_UUID}). No changes made.')
    if original[PATCH_OFFSET:PATCH_OFFSET + 4] != BEFORE:
        found = original[PATCH_OFFSET:PATCH_OFFSET + 4].hex(' ')
        if original[PATCH_OFFSET:PATCH_OFFSET + 4] == AFTER:
            raise ValueError('YTLite is already patched; refusing to patch twice')
        raise ValueError(f'Unexpected code at +0x{PATCH_OFFSET:x}: {found}; no changes made')
    for offset, expected in CONTEXT.items():
        if original[offset:offset + len(expected)] != expected:
            raise ValueError(f'Surrounding instructions changed at +0x{offset:x}; no changes made')
    patched = bytearray(original)
    patched[PATCH_OFFSET:PATCH_OFFSET + 4] = AFTER
    assert len(patched) == len(original)
    assert sum(a != b for a, b in zip(original, patched)) == 4  # each of four bytes differs
    assert macho_uuid(patched) == EXPECTED_UUID
    return bytes(patched)


def patch_ipa(source: Path, destination: Path) -> None:
    if source.resolve() == destination.resolve():
        raise ValueError('Input and output must be different IPA paths')
    if not source.is_file():
        raise ValueError(f'IPA not found: {source}')
    with zipfile.ZipFile(source, 'r') as zin:
        targets = [i for i in zin.infolist() if TARGET_PATTERN.fullmatch(i.filename)]
        if len(targets) != 1:
            raise ValueError(f'Expected one Payload/*.app/Frameworks/YTLite.dylib; found {len(targets)}')
        target_name = targets[0].filename
        # Verify the binary before writing anything to disk.
        original = zin.read(target_name)
        patched = patch_binary(original)
        try:
            with zipfile.ZipFile(destination, 'w') as zout:
                zout.comment = zin.comment
                for info in zin.infolist():
                    if info.filename == target_name:
                        zout.writestr(info, patched)
                    elif info.is_dir():
                        zout.writestr(info, b'')
                    else:
                        with zin.open(info, 'r') as r, zout.open(info, 'w') as w:
                            shutil.copyfileobj(r, w, length=1024 * 1024)
            with zipfile.ZipFile(destination, 'r') as check:
                if check.getinfo(target_name).file_size != len(patched):
                    raise ValueError('IPA output validation: dylib has wrong size')
                if check.read(target_name)[PATCH_OFFSET:PATCH_OFFSET + 4] != AFTER:
                    raise ValueError('IPA output validation: patch was not applied')
        except Exception:
            destination.unlink(missing_ok=True)
            raise
    print(f'PASS: Patched {target_name}')
    print(f'YTLite UUID: {EXPECTED_UUID}')
    print(f'YTLite +0x{PATCH_OFFSET:x}: original BL -> mov x0, xzr')
    print(f'Four instruction bytes changed in YTLite; YouTube executable not modified')
    print(f'Output IPA: {destination}')
    print('EXPERIMENTAL: test regular playback and the quality-selection menu. Sign IPA after patching.')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input_ipa', type=Path)
    p.add_argument('output_ipa', type=Path)
    args = p.parse_args()
    try:
        patch_ipa(args.input_ipa, args.output_ipa)
    except (ValueError, zipfile.BadZipFile, OSError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
