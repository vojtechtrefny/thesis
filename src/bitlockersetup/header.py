# -*- coding: utf-8 -*-
# header.py
# BitLocker on-disk format header
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

from . import constants, utils

class BitLockerHeader():
    """Object representing BitLocker device header (first 512 B)"""

    def __init__(self, device):
        self.device = device

        # read header from the device
        self.raw_data = utils.read_from_device(device, 0, constants.BDE_HEADER_SIZE)

        self.signature = self.raw_data[3:11]
        if self.signature != constants.BD_SIGNATURE:
            raise RuntimeError("Unsupported/unknow device.")

        self.guid = utils.le_decode_uuid(self.raw_data[160:176])

        # get offsets of FVE metadata blocks
        self.fve_metadata_offsets = []
        for offset in constants.FVE_METADATA_BLOCK_HEADER_OFFSETS:
            decoded_offset = utils.le_decode_uint64(self.raw_data[offset:(offset + constants.FVE_METADATA_BLOCK_HEADER_OFFSET_LEN)])
            self.fve_metadata_offsets.append(decoded_offset)

    def __str__(self):
        s = "BitLocker encrypted device\n"
        s += "GUID:\t%s\n" % self.guid

        return s

    def debug_print(self):
        for item in constants.BDE_HEADER:
            item_data = self.raw_data[item[0]:(item[0] + item[1])]

            print("\033[1m%s:\033[0m %s %s" % (item[2], utils.bytes_as_hex(item_data), utils.bytes_decode(item_data)))
