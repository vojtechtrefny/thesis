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
from .errors import HeaderException


class BitLockerHeader():
    """
    Object representing BitLocker device header (first 512 B)

    :param device: full path of the BitLocker device
    :type device: string
    """

    _expected_signature = constants.BD_SIGNATURE
    _guid_offset = 160
    _metadata_offsets = constants.FVE_METADATA_BLOCK_HEADER_OFFSETS

    def __init__(self, device):
        self.device = device

        # read header from the device
        self.raw_data = utils.read_from_device(device, 0, constants.BDE_HEADER_SIZE)

        self._signature = None
        self._guid = None
        self._fve_metadata_offsets = []

    @property
    def signature(self):
        if self._signature is None:
            self._signature = self.raw_data[3:11]

        return self._signature

    @property
    def guid(self):
        if self._guid is None:
            self._guid = utils.le_decode_uuid(self.raw_data[self._guid_offset:self._guid_offset + 16])

        return self._guid

    @property
    def fve_metadata_offsets(self):
        if not self._fve_metadata_offsets:
            for offset in self._metadata_offsets:
                decoded_offset = utils.le_decode_uint64(self.raw_data[offset:(offset + constants.FVE_METADATA_BLOCK_HEADER_OFFSET_LEN)])
                self._fve_metadata_offsets.append(decoded_offset)

        return self._fve_metadata_offsets

    def match(self):
        return self.signature == self._expected_signature

    def __str__(self):
        s = "BitLocker encrypted device\n"
        s += "GUID:\t%s\n" % self.guid

        return s

    def debug_print(self):
        """
        Prints all information in this header for debugging purposes
        """

        for item in constants.BDE_HEADER:
            item_data = self.raw_data[item[0]:(item[0] + item[1])]

            print("\033[1m%s:\033[0m %s %s" % (item[2], utils.bytes_as_hex(item_data), utils.bytes_decode(item_data)))


class BitLockerToGoHeader(BitLockerHeader):
    """
    Object representing BitLocker To Go device header (first 512 B)

    :param device: full path of the BitLocker device
    :type device: string
    """

    _expected_signature = constants.BD_TOGO_SIGNATURE
    _guid_offset = 424
    _metadata_offsets = constants.FVE_METADATA_BLOCK_HEADER_OFFSETS_TOGO

    def __init__(self, device):
        super().__init__(device)

    def debug_print(self):
        raise NotImplementedError


_SUPPORTED_HEADERS = (BitLockerHeader, BitLockerToGoHeader)


def get_header(device):
    for header in _SUPPORTED_HEADERS:
        hinstance = header(device)
        if hinstance.match():
            return hinstance

    raise HeaderException("Unsupported/unknow device.")
