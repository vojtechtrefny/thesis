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

from Cryptodome.Cipher import AES

from bitlockersetup import constants, utils, dm, image
from bitlockersetup.fve import FVE
from bitlockersetup.header import BitLockerHeader
from bitlockersetup.keys import UnecryptedKey


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
        image.decrypt_and_save_image(fve, debug, device, fvek_open_key, os.path.realpath(name))
    elif mode == "dm":
        dm.create_dm_device(fve, device, fvek_open_key, name)


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
