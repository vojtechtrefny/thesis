# -*- coding: utf-8 -*-
# bitlockersetup.py
#
# Copyright (c) 2019 Vojtech Trefny
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import argparse
import getpass
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import AES
from datetime import datetime

from bitlockersetup import constants, utils
from bitlockersetup.fve import FVE
from bitlockersetup.header import BitLockerHeader
from bitlockersetup.keys import UnecryptedKey


def _decrypt_data(key, data, iv_offset):
    decrypted = bytearray()

    sectors = int(len(data) / constants.SECTOR_SIZE)

    for i in range(sectors):
        iv = (int(iv_offset / constants.SECTOR_SIZE) + i).to_bytes(16, "little")  # IV = block number

        cipher = Cipher(algorithms.AES(key), modes.XTS(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        start = i * constants.SECTOR_SIZE
        end = (i * constants.SECTOR_SIZE) + constants.SECTOR_SIZE
        result = decryptor.update(data[start:end]) + decryptor.finalize()
        decrypted.extend(bytearray(result))

    return decrypted


def _read_and_decrypt_data(device, start, count, key, iv_offset):
    """ Read the device sector by sector and decrypt it """
    decrypted = bytearray()

    with open(device, "rb") as f:
        f.seek(start)

        for i in range(0, count, constants.SECTOR_SIZE):
            data = f.read(constants.SECTOR_SIZE)
            decrypted_data = _decrypt_data(key, data, iv_offset + i)
            decrypted.extend(bytearray(decrypted_data))

    return decrypted


def _decrypt_and_save_image(fve, debug, device, fvek_open_key, res_file):
    # first data block
    first_block = fve.volume_header_block
    data_block = utils.read_from_device(device,
                                        first_block.data_offset,
                                        constants.SECTOR_SIZE)

    if debug:
        print("\033[1mFirst sector (encrypted):\033[0m")
        utils.pprint_bytes(data_block)
        print()

    # decrypted first data block
    decrypted_data = _decrypt_data(fvek_open_key.key,
                                   data_block,
                                   first_block.data_offset)

    if debug:
        print("\033[1mFirst sector (decrypted):\033[0m")
        utils.pprint_bytes(decrypted_data)

    # decrypt whole "header" part
    header_data = utils.read_from_device(device,
                                         first_block.data_offset,
                                         first_block.block_size)
    decrypted_header = _decrypt_data(fvek_open_key.key,
                                     header_data,
                                     first_block.data_offset)

    # decrypt everything
    decrypted_everything = _read_and_decrypt_data(device, 8192, fve._device_size - 8192, fvek_open_key.key, 8192)

    # now replace bitlocker metadata with zeroes
    # - 64k after each fve header start
    # - 8k after the encrypted NTFS header start
    for metadata in fve._metadata_starts:
        for i in range(64 * 1024):
            decrypted_everything[metadata + i - 8192] = 0x00

    for i in range(8 * 1024):
        decrypted_everything[fve.volume_header_block.data_offset + i - 8192] = 0x00

    # add some "normal" extension to the decrypted image file
    if not res_file.endswith(".raw"):
        res_file += ".raw"

    # write the decrypted file
    with open(res_file, "wb+") as f:
        f.write(bytes(decrypted_header))
        f.write(bytes(decrypted_everything))

    print("Decrypted image saved to '%s'." % res_file)


def _create_dm_device(fve, device, fvek_open_key, mapper_name):
    first_block = fve.volume_header_block

    crypt_template = "{start} {size} crypt aes-xts-plain64 {key} {iv_offset} {device} {offset}"
    zero_template = "{start} {size} zero"
    table = ""
    start = 0

    # header
    table += crypt_template.format(start=start,
                                   size=int(first_block.block_size / constants.SECTOR_SIZE),
                                   key=utils.bytes_as_hex_dmsetup(fvek_open_key.key),
                                   iv_offset=int(first_block.data_offset / constants.SECTOR_SIZE),
                                   device=device,
                                   offset=int(first_block.data_offset / constants.SECTOR_SIZE))
    start += int(first_block.block_size / constants.SECTOR_SIZE)
    table += r"'\\n'"

    # first data part up to the first fve header
    size = int(fve._metadata_starts[0] / constants.SECTOR_SIZE) - start
    table += crypt_template.format(start=start,
                                   size=size,
                                   key=utils.bytes_as_hex_dmsetup(fvek_open_key.key),
                                   iv_offset=start,
                                   device=device,
                                    offset=start)
    start += size
    table += r"'\\n'"

    # zeroes instead of the first fve header
    size = int(64 * 1024 / constants.SECTOR_SIZE)
    table += zero_template.format(start=start,
                                  size=size)
    start += size
    table += r"'\\n'"

    # zeroes instead of the the "encrypted" ntfs header
    size = int(8 * 1024 / constants.SECTOR_SIZE)
    table += zero_template.format(start=start,
                                  size=size)
    start += size
    table += r"'\\n'"

    # second data part up to the second fve header
    size = int(fve._metadata_starts[1] / constants.SECTOR_SIZE) - start
    table += crypt_template.format(start=start,
                                   size=size,
                                   key=utils.bytes_as_hex_dmsetup(fvek_open_key.key),
                                   iv_offset=start,
                                   device=device,
                                   offset=start)
    start += size
    table += r"'\\n'"

    # zeroes instead of the second fve header
    size = int(64 * 1024 / constants.SECTOR_SIZE)
    table += zero_template.format(start=start,
                                  size=size)
    start += size
    table += r"'\\n'"

    # third data part up to the third fve header
    size = int(fve._metadata_starts[2] / constants.SECTOR_SIZE) - start
    table += crypt_template.format(start=start,
                                   size=size,
                                   key=utils.bytes_as_hex_dmsetup(fvek_open_key.key),
                                   iv_offset=start,
                                   device=device,
                                   offset=start)
    start += size
    table += r"'\\n'"

    # zeroes instead of the third fve header
    size = int(64 * 1024 / constants.SECTOR_SIZE)
    table += zero_template.format(start=start,
                                  size=size)
    start += size
    table += r"'\\n'"

    # fourth (and last) part of the data
    size = int(fve._device_size / constants.SECTOR_SIZE) - start
    table += crypt_template.format(start=start,
                                   size=size,
                                   key=utils.bytes_as_hex_dmsetup(fvek_open_key.key),
                                   iv_offset=start,
                                   device=device,
                                   offset=start)

    # dmsetup command
    cmd = "echo -e '%s' | dmsetup create %s" % (table, mapper_name)

    ret, out = utils.run_command(cmd)
    if ret != 0:
        print("Failed to create device mapper device: %s" % out)
        sys.exit(1)

    print("Created device mapper device '/dev/mapper/%s'." % mapper_name)


def main(device, debug, password, mode, name):
    # read first 512 bytes and parse bitlocker header
    header = BitLockerHeader(device)

    fve = FVE(device, header)
    if debug:
        print(fve)

    vmks = fve.vmks
    fvek = fve.fvek

    # get the VMK protected by password and calculate VMK key from it
    pw_vmk = next(v for v in vmks if v.is_password_protected)
    pw_vmk_key = utils.get_key_from_password(password, pw_vmk.salt)

    # decrypt the VMK
    encryption_suite = AES.new(pw_vmk_key, AES.MODE_CCM, pw_vmk.aes_key.raw_nonce)
    decrypted_data = encryption_suite.decrypt_and_verify(pw_vmk.aes_key.key, received_mac_tag=pw_vmk.aes_key.mac_tag)
    vmk_open_key1 = UnecryptedKey(decrypted_data)

    # and use it to decrypt the FVEK
    encryption_suite = AES.new(vmk_open_key1.key, AES.MODE_CCM, fvek.raw_nonce)
    decrypted_data = encryption_suite.decrypt_and_verify(fvek.key, received_mac_tag=fvek.mac_tag)

    fvek_open_key = UnecryptedKey(decrypted_data)

    if debug:
        print(fvek_open_key)

    if mode == "image":
        _decrypt_and_save_image(fve, debug, device, fvek_open_key, os.path.realpath(name))
    elif mode == "dm":
        _create_dm_device(fve, device, fvek_open_key, name)


if __name__ == '__main__':

    argparser = argparse.ArgumentParser()
    argparser.add_argument("device", help="device (or image) to unlock")
    argparser.add_argument("name", help="name for the dm device or ecnrypted image")
    argparser.add_argument("-v", "--verbose", dest="verbose", help="enable debug messages",
                           action="store_true")
    argparser.add_argument("-m", "--mode", dest="mode", help="mode -- either 'image' or 'dm' (default is 'dm')",
                           action="store")
    args = argparser.parse_args()

    # default mode -- device mapper
    if not args.mode:
        args.mode = "dm"

    if args.mode not in ["image", "dm"]:
        print("Unknown mode '%s'" % args.mode, file=sys.stderr)
        sys.exit(1)

    if args.mode == "dm" and os.getuid() != 0:
        print("Must be run as root in device mapper mode", file=sys.stderr)
        sys.exit(1)

    if args.mode == "image" and not os.access(os.path.realpath(args.name), os.W_OK):
        print("Can't save decrypted image as '%s', not writable." % os.path.realpath(args.name), file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.device):
        print("Device '%s' doesn't exist." % args.device, file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass(prompt="Password for '%s': " % args.device)

    main(device=args.device, debug=args.verbose, password=password, mode=args.mode, name=args.name)
