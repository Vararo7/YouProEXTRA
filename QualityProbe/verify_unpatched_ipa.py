#!/usr/bin/env python3
"""Check the exact UNPATCHED 21.44.4 executable before running Probe 0.3."""
from pathlib import Path
import sys
from zipfile import ZipFile

EXPECTED_UUID = bytes.fromhex('fe890cb6603b3adcbc140860a8b64e40')
MOV_OFFSET = 0x4919AC
ORIGINAL_MOV_TWO = bytes.fromhex('43 00 80 52')
PATCHED_MOV_ZERO = bytes.fromhex('03 00 80 52')
BL_OFFSET = 0x4919B0
ORIGINAL_BL = bytes.fromhex('59 ea dd 95')


def verify(exe):
    if EXPECTED_UUID not in exe[:0x4000]:
        raise ValueError('Unexpected Mach-O UUID; require exact tested 21.44.4 executable')
    instruction = exe[MOV_OFFSET:MOV_OFFSET + 4]
    if instruction == PATCHED_MOV_ZERO:
        raise ValueError('The old count=0 instruction patch is PRESENT; remove it from the workflow')
    if instruction != ORIGINAL_MOV_TWO:
        raise ValueError(f'Unexpected instruction at 0x{MOV_OFFSET:x}: {instruction.hex()}')
    if exe[BL_OFFSET:BL_OFFSET + 4] != ORIGINAL_BL:
        raise ValueError('Original Objective-C array call does not match tested executable')


def main():
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 QualityProbe/verify_unpatched_ipa.py youtube.ipa')
    try:
        with ZipFile(Path(sys.argv[1])) as z:
            matches = [name for name in z.namelist()
                       if name.startswith('Payload/') and name.endswith('.app/YouTube')]
            if len(matches) != 1:
                raise ValueError(f'Expected one YouTube executable, got {matches}')
            verify(z.read(matches[0]))
    except (OSError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('PASS: Original YouTube 21.44.4 array count=2 and BL instruction verified; no binary patch.')


if __name__ == '__main__':
    main()
