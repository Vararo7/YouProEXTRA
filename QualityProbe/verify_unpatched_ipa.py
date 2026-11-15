#!/usr/bin/env python3
"""Reject IPAs other than the observed, unpatched YouTube 21.46.3 binary.

This is a safety check for a version-specific diagnostic; it does NOT patch.
"""
from pathlib import Path
import sys
import struct
from zipfile import ZipFile

EXPECTED_UUID = bytes.fromhex('d5512842941b3ecf8b7b258d3ee0fc5a')
METHOD_OFFSET = 0x48FCB4
HELPER_INPUT_OFFSET = 0x48FE14
HELPER_CALL_OFFSET = 0x48FE18
FIELD_STORE_OFFSET = 0x48FE28
PROVIDER_LOAD_OFFSET = 0x48FE88
MOV_OFFSET = 0x48FEC8
ARRAY_CALL_OFFSET = 0x48FECC

ORIGINAL_METHOD_START = bytes.fromhex('ff c3 01 d1')
ORIGINAL_HELPER_INPUT = bytes.fromhex('e0 03 13 aa')
ORIGINAL_HELPER_CALL = bytes.fromhex('d4 67 f1 97')
ORIGINAL_FIELD_STORE = bytes.fromhex('c0 02 00 f9')
ORIGINAL_PROVIDER_LOAD = bytes.fromhex('80 0e 40 f9')
ORIGINAL_MOV_TWO = bytes.fromhex('43 00 80 52')
PATCHED_MOV_ZERO = bytes.fromhex('03 00 80 52')
ORIGINAL_ARRAY_CALL = bytes.fromhex('9e fd dd 95')


def macho_uuid(exe):
    if len(exe) < 32 or exe[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('Not a 64-bit little-endian Mach-O executable')
    ncmds, sizeofcmds = struct.unpack_from('<II', exe, 16)
    cursor = 32
    end = cursor + sizeofcmds
    if end > len(exe) or ncmds > 1000:
        raise ValueError('Malformed Mach-O load commands')
    for _ in range(ncmds):
        if cursor + 8 > end:
            raise ValueError('Truncated load command')
        cmd, cmdsize = struct.unpack_from('<II', exe, cursor)
        if cmdsize < 8 or cursor + cmdsize > end:
            raise ValueError('Malformed load-command size')
        if cmd == 0x1b:  # LC_UUID
            if cmdsize != 24:
                raise ValueError('Malformed LC_UUID')
            return exe[cursor + 8:cursor + 24]
        cursor += cmdsize
    raise ValueError('No LC_UUID found')


def verify(exe):
    actual_uuid = macho_uuid(exe)
    if actual_uuid != EXPECTED_UUID:
        raise ValueError(f'Incorrect YouTube binary UUID: {actual_uuid.hex()} — requires unpatched 21.46.3 supplied executable')
    if b'21.46.3\x00' not in exe:
        raise ValueError('Version marker 21.46.3 not found')
    for label, off, expected in [
        ('controller method', METHOD_OFFSET, ORIGINAL_METHOD_START),
        ('helper input', HELPER_INPUT_OFFSET, ORIGINAL_HELPER_INPUT),
        ('helper call', HELPER_CALL_OFFSET, ORIGINAL_HELPER_CALL),
        ('scope field store', FIELD_STORE_OFFSET, ORIGINAL_FIELD_STORE),
        ('provider receiver load', PROVIDER_LOAD_OFFSET, ORIGINAL_PROVIDER_LOAD),
        ('array call', ARRAY_CALL_OFFSET, ORIGINAL_ARRAY_CALL),
    ]:
        found = exe[off:off + 4]
        if found != expected:
            raise ValueError(f'{label} instruction mismatch at +0x{off:x}: {found.hex()} != {expected.hex()}')
    mov = exe[MOV_OFFSET:MOV_OFFSET + 4]
    if mov == PATCHED_MOV_ZERO:
        raise ValueError('Old count=0 patch detected; Probe 0.8 needs an original count=2 binary')
    if mov != ORIGINAL_MOV_TWO:
        raise ValueError(f'Unexpected array-count instruction +0x{MOV_OFFSET:x}: {mov.hex()}')


def main():
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 QualityProbe/verify_unpatched_ipa.py youtube.ipa')
    try:
        with ZipFile(Path(sys.argv[1])) as z:
            matches = [name for name in z.namelist() if name.startswith('Payload/') and name.endswith('.app/YouTube')]
            if len(matches) != 1:
                raise ValueError(f'Expected exactly one YouTube executable, got {matches}')
            verify(z.read(matches[0]))
    except (OSError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('PASS: Original YouTube 21.46.3 (UUID d5512842-941b-3ecf-8b7b-258d3ee0fc5a), quality initializer and array call verified; unpatched count=2.')

if __name__ == '__main__':
    main()
