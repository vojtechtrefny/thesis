# -*- coding: utf-8 -*-
# entry.py
# Metadata entry
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
from .keys import VMK, FVEK, AESEncryptedKey


class MetadataEntry():
    """
    Object representing BitLocker metadata entry

    :param raw_data: raw data to parse
    :type raw_data: bytes
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

        self.entry_header = raw_data[0:8]
        self.entry_data = raw_data[8:]

        self.size = utils.le_decode_uint8(self.entry_header[0:2])
        self.type = utils.le_decode_uint8(self.entry_header[2:4])
        self.value = utils.le_decode_uint8(self.entry_header[4:6])

        self._vmk = None
        self._fvek = None
        self._aes_key = None

        if self.is_stretch_key:
            self.salt = self.entry_data[4:20]
        if self.is_volume_header:
            self.data_offset = utils.le_decode_uint64(self.entry_data[0:8])
            self.block_size = utils.le_decode_uint64(self.entry_data[8:16])

    def __repr__(self):
        return "MetadataEntry ('%s': '%s')" % (constants.FVE_ENTRY_TYPES[self.type],
                                               constants.FVE_VALUE_TYPES[self.value])

    def __str__(self):
        if self.is_vmk:
            return str(self.vmk)
        elif self.is_fvek:
            return str(self.fvek)
        elif self.is_description:
            return "Description:\t\t%s\n" % self.description
        elif self.is_stretch_key:
            return "\tSalt:\t\t%s\n" % utils.bytes_as_hex(self.salt)
        elif self.is_aes_key:
            return str(self.aes_key)
        elif self.is_volume_header:
            return ""  # nothing special to print here
        else:
            return "Unknown metadata entry. Type: %s, Value: %s" % (constants.FVE_ENTRY_TYPES[self.type],
                                                                    constants.FVE_VALUE_TYPES[self.value])

    def debug_print(self):
        """
        Prints all information in this header for debugging purposes
        """

        s = "Metadata entry:\n"
        s += "\tType: %s\n" % constants.FVE_ENTRY_TYPES[self.type]
        s += "\tValue: %s\n" % constants.FVE_VALUE_TYPES[self.value]

        print(s)

    @property
    def vmk(self):
        """
        VMK found in this metadata (result is valid only if this is a VMK entry
        (see :func:`~bitlockersetup.entry.MetadataEntry.is_vmk`)

        :rtype: :func:`~bitlockersetup.keys.VMK`
        """

        if not self.is_vmk:
            return None

        if self._vmk is None:
            self._vmk = VMK(self.entry_data)

        return self._vmk

    @property
    def fvek(self):
        """
        FVEK found in this metadata (result is valid only if this is a FVEK entry
        (see :func:`~bitlockersetup.entry.MetadataEntry.is_fvek`)

        :rtype: :func:`~bitlockersetup.keys.VMK`
        """

        if not self.is_fvek:
            return None

        if self._fvek is None:
            self._fvek = FVEK(self.entry_data)

        return self._fvek

    @property
    def aes_key(self):
        """
        Encrypted key found in this metadata (result is valid only if this is an
        encrypted key entry (see :func:`~bitlockersetup.entry.MetadataEntry.is_aes_key`)

        :rtype: :func:`~bitlockersetup.keys.AESEncryptedKey`
        """

        if not self.is_aes_key:
            return None

        if self._aes_key is None:
            self._aes_key = AESEncryptedKey(self.entry_data)

        return self._aes_key

    @property
    def description(self):
        """
        Description found in this metadata (result is valid only if this is a
        description (see :func:`~bitlockersetup.entry.MetadataEntry.is_description`)

        :rtype: string
        """
        if not self.is_description:
            return None

        return self.entry_data.decode("utf-16")

    @property
    def is_description(self):
        return self.type == 0x0007

    @property
    def is_vmk(self):
        return self.type == 0x0002

    @property
    def is_fvek(self):
        return self.type == 0x0003

    @property
    def is_property(self):
        return self.type == 0x0000

    @property
    def is_volume_header(self):
        return self.type == 0x000f

    @property
    def is_stretch_key(self):
        return self.is_property and self.value == 0x0003

    @property
    def is_aes_key(self):
        return self.is_property and self.value == 0x0005
