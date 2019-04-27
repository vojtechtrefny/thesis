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

from enum import Enum
from distutils.util import strtobool

from bitlockersetup import constants, utils, dm, image, errors
from bitlockersetup.fve import FVE
from bitlockersetup.header import BitLockerHeader
from bitlockersetup.keys import UnecryptedKey


class Modes(Enum):
    OPEN = 1
    CLOSE = 2
    IMAGE = 3
    DUMP = 4
    UUID = 5


def open(device, debug, password, mode, name):
    fve = _parse_metadata(device)
    if debug:
        print(fve)

    fvek_open_key = fve.get_fvek_by_passphrase(password)

    if debug:
        print(fvek_open_key)

    if mode == Modes.IMAGE:
        image.decrypt_and_save_image(fve, debug, device, fvek_open_key, os.path.realpath(name))
    elif mode == Modes.OPEN:
        dm.create_dm_device(fve, device, fvek_open_key, name)


def _parse_metadata(device):
    header = BitLockerHeader(device)
    fve = FVE(device, header)

    return fve


def main(args):
    # these modes need root access
    if args.mode in (Modes.OPEN, Modes.CLOSE) and os.getuid() != 0:
        print("Must be run as root open or close devices.", file=sys.stderr)
        return False

    # these modes need an existing block devices
    if args.mode in (Modes.OPEN, Modes.IMAGE, Modes.DUMP, Modes.UUID) and \
       not os.path.exists(args.device):
        print("Device '%s' doesn't exist." % args.device, file=sys.stderr)
        return False

    # close
    if args.mode == Modes.CLOSE:
        dm_devices = dm.get_dm_devices()
        if args.device not in dm_devices:
            print("Device '%s' doesn't appear to be an existing DM device." % args.device, file=sys.stderr)
            return False

        try:
            dm.close_device(args.device)
        except errors.DMDeviceException as e:
            print("Failed to remove device '%s': %s" % (args.device, str(e)), file=sys.stderr)
            return False

    # open and image
    if args.mode in (Modes.OPEN, Modes.IMAGE):
        if args.mode == Modes.IMAGE and os.path.exists("./" + args.filename):
            rewrite = input("File '%s' already exists. Replace [Y/n]? " % args.filename)
            if rewrite not in ("yes", "YES", "Yes", "y", "Y", ""):
                return True

        password = getpass.getpass(prompt="Password for '%s': " % args.device)

        open(device=args.device, debug=args.verbose, password=password,
             mode=args.mode, name="bitlocker")  # FIXME

    # dump
    if args.mode == Modes.DUMP:
        fve = _parse_metadata(args.device)
        print(fve)

    # uuid
    if args.mode == Modes.UUID:
        fve = _parse_metadata(args.device)
        print(fve.guid)

    return True


if __name__ == '__main__':

    argparser = argparse.ArgumentParser()
    argparser.add_argument("-v", "--verbose", dest="verbose", help="enable debug messages",
                           action="store_true")
    subparsers = argparser.add_subparsers(help='sub-command help')

    # subparser for the 'open' command
    parser_open = subparsers.add_parser("open", help="Open a BitLocker device")
    parser_open.add_argument("device", help="device to open")
    parser_open.add_argument("name", help="name for the open device (optional)", nargs="?", default=None)
    parser_open.set_defaults(mode=Modes.OPEN)

    # subparser for the 'close' command
    parser_close = subparsers.add_parser("close", help="Close an opened BitLocker device")
    parser_close.add_argument("device", help="device to close")
    parser_close.set_defaults(mode=Modes.CLOSE)

    # subparser for the 'image' command
    parser_image = subparsers.add_parser("image", help="Decrypt a BitLocker device and save it as an image")
    parser_image.add_argument("device", help="device to decrypt")
    parser_image.add_argument("filename", help="name for the decrypted image")
    parser_image.set_defaults(mode=Modes.IMAGE)

    # subparser for the 'dump' command
    parser_dump = subparsers.add_parser("dump", help="Print information about a BitLocker device")
    parser_dump.add_argument("device", help="device to dump")
    parser_dump.set_defaults(mode=Modes.DUMP)

    # subparser for the 'uuid' command
    parser_uuid = subparsers.add_parser("uuid", help="Print UUID (GUID) of a BitLocker device")
    parser_uuid.add_argument("device", help="device to print UUID for")
    parser_uuid.set_defaults(mode=Modes.UUID)

    args = argparser.parse_args()

    success = main(args)

    if success:
        sys.exit(0)
    else:
        sys.exit(1)
