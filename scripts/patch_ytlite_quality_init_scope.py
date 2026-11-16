#!/usr/bin/env python3
"""Experimental YTLite 6.0 quality-controller initializer argument forwarding.

Usage: python3 patch_ytlite_quality_init_scope.py input.ipa output.ipa

Changes ONLY the specific YTLite.dylib identified by UUID
4294bd0c-2755-34f7-8405-003d18893302, when paired with YouTube
21.46.3 UUID d5512842-941b-3ecf-8b7b-258d3ee0fc5a.

At YTLite+0x3DC18 and +0x3DC1C, replace:
    mov x2, #0  -> ldr x2, [x21, #8]
    mov x3, #0  -> mov x3, x19

The replacement mirrors YouTube 21.46.3's own factory call at
YouTube+0x48FC2C and +0x48FC30. The fix has NOT been device-tested.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import re
import shutil
import struct
import sys
import uuid
import zipfile
from pathlib import Path

YTLITE_UUID = uuid.UUID('4294bd0c-2755-34f7-8405-003d18893302')
YOUTUBE_UUID = uuid.UUID('d5512842-941b-3ecf-8b7b-258d3ee0fc5a')
YTLITE_MEMBER = re.compile(r'Payload/[^/]+\.app/Frameworks/YTLite\.dylib\Z')
YOUTUBE_MEMBER = re.compile(r'Payload/[^/]+\.app/YouTube\Z')
# 4-byte little-endian ARM64 instructions
PATCHES = {
    0x3DC18: (bytes.fromhex('02 00 80 d2'), bytes.fromhex('a2 06 40 f9')),
    0x3DC1C: (bytes.fromhex('03 00 80 d2'), bytes.fromhex('e3 03 13 aa')),
}
# Ensure we really have the exact control flow and that the *old guard*
# has NOT already removed the controller allocation.
YTLITE_CONTEXT = {
    0x3D7E4: bytes.fromhex('f3 03 02 aa'),  # x19 = first explicit argument
    0x3D7E8: bytes.fromhex('f4 03 01 aa'),  # x20 = selector
    0x3D7EC: bytes.fromhex('f5 03 00 aa'),  # x21 = self
    0x3DC08: bytes.fromhex('0a 9b 5d 94'),  # obtain controller class
    0x3DC0C: bytes.fromhex('fe 08 00 94'),  # allocate controller (must NOT be old guard)
    0x3DC14: bytes.fromhex('01 15 46 f9'),  # selector reference
    0x3DC20: bytes.fromhex('01 09 00 94'),  # call initializer
    0x3DC24: bytes.fromhex('f7 03 00 aa'),  # remember returned controller
    0x3DC38: bytes.fromhex('03 09 00 94'),  # pass to setter
}
# The first pair is the source of the idea: YouTube's factory sends
# its [self+8] as serviceRegistryScope and the caller-supplied responder.
YOUTUBE_FACTORY = {
    0x48FBC8: bytes.fromhex('f5 03 00 aa'), # x21 = self
    0x48FC2C: bytes.fromhex('a2 06 40 f9'), # x2 = [x21 + 8]
    0x48FC30: bytes.fromhex('e3 03 13 aa'), # x3 = x19 (parent)
}


def macho_uuid(blob: bytes) -> uuid.UUID:
    if len(blob) < 32:
        raise ValueError('Invalid Mach-O header (too small)')
    magic, cpu_type, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from('<IiiIIIII', blob)
    if magic != 0xFEEDFACF or cpu_type != 0x0100000C:
        raise ValueError('Expected a 64-bit ARM64 Mach-O binary')
    limit = 32 + sizeofcmds
    if ncmds > 10000 or limit > len(blob):
        raise ValueError('Invalid Mach-O load command range')
    pos = 32
    for _ in range(ncmds):
        if pos + 8 > limit:
            raise ValueError('Truncated Mach-O command')
        cmd, size = struct.unpack_from('<II', blob, pos)
        if size < 8 or pos + size > limit:
            raise ValueError('Invalid Mach-O load command size')
        if cmd == 0x1B:
            if size != 24:
                raise ValueError('Invalid Mach-O UUID command')
            return uuid.UUID(bytes=bytes(blob[pos+8:pos+24]))
        pos += size
    raise ValueError('No Mach-O UUID found')


def assert_bytes(blob: bytes, expected: dict[int, bytes], name: str) -> None:
    for off, value in expected.items():
        found = blob[off:off+len(value)]
        if found != value:
            raise ValueError(f'{name}: byte mismatch at +0x{off:X}; '
                             f'expected {value.hex(" ")}, got {found.hex(" ")}. '
                             'Wrong or previously patched binary: no changes made.')


def patch_ytlite(ytlite: bytes, youtube: bytes) -> bytes:
    yt_uuid = macho_uuid(youtube)
    tweak_uuid = macho_uuid(ytlite)
    if yt_uuid != YOUTUBE_UUID:
        raise ValueError(f'Wrong YouTube UUID {yt_uuid}; expected {YOUTUBE_UUID} (21.46.3).')
    if tweak_uuid != YTLITE_UUID:
        raise ValueError(f'Wrong YTLite UUID {tweak_uuid}; expected {YTLITE_UUID}.')
    assert_bytes(youtube, YOUTUBE_FACTORY, 'YouTube factory verification')
    assert_bytes(ytlite, YTLITE_CONTEXT, 'YTLite call-path verification')
    assert_bytes(ytlite, {k: v[0] for k,v in PATCHES.items()}, 'YTLite patch verification')
    out = bytearray(ytlite)
    for off, (old, new) in PATCHES.items():
        out[off:off+len(old)] = new
    if macho_uuid(out) != YTLITE_UUID:
        raise AssertionError('Patch unexpectedly changed the YTLite UUID')
    assert_bytes(out, {k: v[1] for k,v in PATCHES.items()}, 'YTLite post-patch verification')
    diffs = [i for i,(a,b) in enumerate(zip(ytlite, out)) if a != b]
    if not diffs or not all(i in range(0x3DC18,0x3DC20) for i in diffs):
        raise AssertionError('Unexpected changes outside the two target instructions')
    return bytes(out)


def patch_ipa(source: Path, dest: Path) -> None:
    if source.resolve() == dest.resolve():
        raise ValueError('Input and output IPA paths must differ')
    if not source.is_file():
        raise ValueError(f'Input IPA not found: {source}')
    with zipfile.ZipFile(source) as zin:
        tweak_names = [i.filename for i in zin.infolist() if YTLITE_MEMBER.fullmatch(i.filename)]
        yt_names = [i.filename for i in zin.infolist() if YOUTUBE_MEMBER.fullmatch(i.filename)]
        if len(tweak_names) != 1 or len(yt_names) != 1:
            raise ValueError(f'Expected one YouTube and one YTLite inside IPA; found {len(yt_names)} and {len(tweak_names)}')
        tweak_name, yt_name = tweak_names[0], yt_names[0]
        if tweak_name.split('/')[1] != yt_name.split('/')[1]:
            raise ValueError('YTLite and YouTube are from different app bundles')
        original = zin.read(tweak_name)
        youtube_data = zin.read(yt_name)
        youtube_sha256 = hashlib.sha256(youtube_data).digest()
        replacement = patch_ytlite(original, youtube_data)
        del youtube_data
        try:
            with zipfile.ZipFile(dest, 'w') as zout:
                zout.comment = zin.comment
                for info in zin.infolist():
                    if info.filename == tweak_name:
                        zout.writestr(copy.copy(info), replacement)
                    elif info.is_dir():
                        zout.writestr(copy.copy(info), b'')
                    else:
                        with zin.open(info) as input_stream, zout.open(copy.copy(info), 'w') as output_stream:
                            shutil.copyfileobj(input_stream, output_stream, 1024*1024)
            with zipfile.ZipFile(dest) as check:
                assert_bytes(check.read(tweak_name), {k:v[1] for k,v in PATCHES.items()}, 'Output IPA')
                youtube_check = hashlib.sha256()
                with check.open(yt_name) as youtube_stream:
                    for chunk in iter(lambda: youtube_stream.read(1024*1024), b''):
                        youtube_check.update(chunk)
                if youtube_check.digest() != youtube_sha256:
                    raise AssertionError('YouTube executable was unexpectedly changed')
        except Exception:
            dest.unlink(missing_ok=True)
            raise
    print('PASS: YTLite quality controller initialization argument patch applied')
    print(f'YouTube UUID: {YOUTUBE_UUID}; YTLite UUID: {YTLITE_UUID}')
    print('YTLite +0x3DC18: mov x2, #0 -> ldr x2, [x21, #8]')
    print('YTLite +0x3DC1C: mov x3, #0 -> mov x3, x19')
    print('YouTube executable not modified. IPA ready for signing.')
    print('EXPERIMENTAL: Preserve the known-working guard build and test on one device.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input_ipa', type=Path)
    parser.add_argument('output_ipa', type=Path)
    args = parser.parse_args()
    try:
        patch_ipa(args.input_ipa, args.output_ipa)
    except (ValueError, zipfile.BadZipFile, OSError, AssertionError) as e:
        print('ERROR:', e, file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
