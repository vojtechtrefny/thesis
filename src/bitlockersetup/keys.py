# -*- coding: utf-8 -*-
# keys.py
# Enryption keys used in BitLocker
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

from datetime import datetime

from . import constants, utils


class VMK():
    """
    Object representing BitLocker VMK

    :param raw_data: raw data to parse
    :type raw_data: bytes
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

        self.header = raw_data[0:28]
        self.data = raw_data[28:]

        self.identifier = utils.le_decode_uuid(self.header[0:16])
        self.protection = utils.le_decode_uint8(self.header[26:28])

        self._entries = []

        self._parse_entries()

    def __str__(self):
        s = "\033[1mVMK\033[0m\n"
        s += "\tIdentifier:\t%s\n" % self.identifier
        s += "\tType:\t\t%s\n" % constants.KEY_PROTECTION_TYPES[self.protection]

        for entry in self._entries:
            s += str(entry)

        return s

    def _parse_entries(self):
        # we need to import it here to avoid circular dependencies
        from .entry import MetadataEntry

        # 'data' part of the VMK is just another array of metadata entries
        start = 0
        end = len(self.data)

        while (end - start) > 2:
            metadata_entry_len = utils.le_decode_uint8(self.data[start:(start + 2)])

            # no more entries
            if metadata_entry_len == 0:
                break

            entry = MetadataEntry(self.data[start:(start + metadata_entry_len)])
            self._entries.append(entry)

            start += metadata_entry_len

    @property
    def is_password_protected(self):
        return self.protection == 0x2000

    @property
    def is_recovery_protected(self):
        return self.protection == 0x0800

    @property
    def salt(self):
        """
        Salt string associated with this VMK

        :rtype: bytes
        """
        for entry in self._entries:
            if entry.is_stretch_key:
                return entry.salt

        raise RuntimeError("No salt for this VMK")

    @property
    def aes_key(self):
        """
        An actuall key metadata "container" with this VMK

        :rtype: :func:`~bitlockersetup.keys.AESEncryptedKey`
        """
        for entry in self._entries:
            if entry.is_aes_key:
                return entry.aes_key

        raise RuntimeError("No key for this VMK")


class AESEncryptedKey():
    """
    Object representing AES encrypted key in a metadata entry

    :param raw_data: raw data to parse
    :type raw_data: bytes
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

        self.raw_nonce = self.raw_data[0:12]

        win_time = utils.le_decode_uint64(self.raw_data[0:8])
        self.nonce = datetime.utcfromtimestamp(utils.filetime_to_unixtime(win_time))

        self.counter = utils.le_decode_uint32(self.raw_data[8:12])
        self.mac_tag = self.raw_data[12:28]
        self.key = self.raw_data[28:]

    def __str__(self):
        s = "\tAES-CCM encrypted key\n"
        s += "\t\tNonce data:\t%s\n" % self.nonce
        s += "\t\tNonce counter:\t%s\n" % self.counter
        s += "\t\tKey:\t %s\n" % utils.bytes_as_hex(self.key)

        return s


class FVEK(AESEncryptedKey):
    """
    Object representing BitLocker FVEK

    :param raw_data: raw data to parse
    :type raw_data: bytes
    """

    def __str__(self):
        s = "\033[1mFVEK\033[0m\n"
        s += super().__str__()

        return s


class UnecryptedKey():
    """
    Object representing a decrypted key (VMK or FVEK)

    :param raw_data: raw data to parse
    :type raw_data: bytes
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

        self.size = utils.le_decode_uint32(self.raw_data[0:4])
        self.encryption = utils.le_decode_uint16(self.raw_data[8:12])
        self.key = self.raw_data[12:]

    def __str__(self):
        encryption_str = constants.ENCRYPTION_METHODS[self.encryption]

        s = "\033[1mUnecrypted key\033[0m\n"
        s += "\tEncryption method:\t%s\n" % encryption_str
        s += "\tKey:\t %s\n" % utils.bytes_as_hex(self.key)

        return s
