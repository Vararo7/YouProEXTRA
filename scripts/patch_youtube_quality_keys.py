#!/usr/bin/env python3
"""Experimental patch for YouTube 21.44.4 (UUID fe890cb6-603b-3adc-bc14-0860a8b64e40).

The Objective-C array created at YouTube +0x4919ac contains the values returned
by persistentVideoQualityWifiKey and persistentVideoQualityMobileKey.
This test changes its element count from 2 to 0, so the nil Wi-Fi key cannot
cause NSInvalidArgumentException at that call. It intentionally DISABLES the
collection of both preference keys; behavior downstream is not guaranteed.

Usage: python3 patch_youtube_quality_keys.py input.ipa output.ipa
       python3 patch_youtube_quality_keys.py YouTube YouTube.patched

The resulting IPA is unsigned / has invalid signatures until it is processed
and signed again with the normal IPA injector/signer. Do not distribute it as
an already-signed app.
"""
import argparse
import pathlib
import zipfile

EXPECTED_UUID = bytes.fromhex('fe890cb6603b3adcbc140860a8b64e40')
FILE_OFFSET = 0x4919AC
BEFORE = bytes.fromhex('43 00 80 52')  # ARM64: mov w3, #2
AFTER = bytes.fromhex('03 00 80 52')   # ARM64: mov w3, #0


def patch(blob):
    if EXPECTED_UUID not in blob[:0x4000]:
        raise ValueError('YouTube Mach-O UUID mismatch: not the tested 21.44.4 binary')
    if blob[FILE_OFFSET:FILE_OFFSET+4] != BEFORE:
        raise ValueError('Unexpected instruction at 0x4919ac; refusing unsafe patch')
    result = bytearray(blob)
    result[FILE_OFFSET:FILE_OFFSET+4] = AFTER
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error('Use a different output path to preserve the original')
    if args.input.suffix.lower() == '.ipa':
        with zipfile.ZipFile(args.input, 'r') as source:
            matches = [x.filename for x in source.infolist() if x.filename.startswith('Payload/') and x.filename.endswith('.app/YouTube')]
            if len(matches) != 1:
                raise ValueError(f'Expected exactly one YouTube executable, got {matches}')
            executable = matches[0]
            replacement = patch(source.read(executable))
            with zipfile.ZipFile(args.output, 'w') as result:
                for info in source.infolist():
                    data = replacement if info.filename == executable else source.read(info.filename)
                    result.writestr(info, data)
    else:
        args.output.write_bytes(patch(args.input.read_bytes()))
    print('Experimental one-instruction patch applied:', args.output)
    print('REMINDER: not a proven complete fix; rebuild/re-sign IPA before installing')


if __name__ == '__main__':
    main()
