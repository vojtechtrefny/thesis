# -*- coding: utf-8 -*-
# fve.py
# BitLocker FVE metadata header
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
from .entry import MetadataEntry
from .errors import FVEException
from .keys import UnecryptedKey

from Cryptodome.Cipher import AES


class FVE():
    """Object representing BitLocker FVE headers"""

    def __init__(self, device, bde_header):

        self.device = device
        self.bde_header = bde_header

        self._metadata_block_headers = []
        self._metadata_headers = []
        self._metadata_starts = []

        self._entries = []

        self._metadata_size = 0
        self._device_size = 0

        self._guid = None

        self._parse()

    def _parse(self):
        self._parse_headers()
        self._verify_headers()
        self._get_metadata_entries()

    def _parse_headers(self):
        # there actually three copies of the FVE, just go throught all of them
        for offset in self.bde_header.fve_metadata_offsets:
            block_header_start = offset
            block_header_end = offset + constants.FVE_METADATA_BLOCK_HEADER_LEN

            # read the metadata block header (64 bytes)
            fve_metadata_block = utils.read_from_device(self.device,
                                                        block_header_start,
                                                        constants.FVE_METADATA_BLOCK_HEADER_LEN)
            self._metadata_block_headers.append(fve_metadata_block)

            # read the metadata header (48 bytes starting immediately after metadata block header)
            fve_metadata_header = utils.read_from_device(self.device,
                                                         block_header_end,
                                                         constants.FVE_METADATA_HEADER_LEN)
            self._metadata_headers.append(fve_metadata_header)
            self._metadata_starts.append(block_header_start)

        self._metadata_size = utils.le_decode_uint32(self.header[0:4])
        self._device_size = utils.le_decode_uint64(self._metadata_block_headers[0][16:24])

    def _verify_headers(self):
        # we have three headers, just make sure all of them are the same
        if not all(m == self._metadata_block_headers[0] for m in self._metadata_block_headers):
            raise RuntimeError("FVE metadata block headers mismatch")

        if not all(m == self._metadata_headers[0] for m in self._metadata_headers):
            raise RuntimeError("FVE metadata headers mismatch")

    def _get_metadata_entries(self):
        # metadata entries just start after every FVE header, we read entries
        # from the first FVE block, because we just checked all three are same
        entry_start = self._metadata_starts[0] + constants.FVE_METADATA_BLOCK_HEADER_LEN + constants.FVE_METADATA_HEADER_LEN

        entries_data = utils.read_from_device(self.device,
                                              entry_start,
                                              self._metadata_size)

        # we don't know how many entries there are, so just read until there is
        # at least two bytes to read (entry lenght)
        start = 0
        end = self._metadata_size

        while (end - start) > 2:
            metadata_entry_len = utils.le_decode_uint8(entries_data[start:(start + 2)])

            # no more entries
            if metadata_entry_len == 0:
                break

            entry = MetadataEntry(entries_data[start:(start + metadata_entry_len)])
            self._entries.append(entry)

            start += metadata_entry_len

    def debug_print(self):
        print("==== FVE metadata block header ====")
        utils.print_header(self.block_header, constants.FVE_METADATA_BLOCK_HEADER)

        print("==== FVE metadata header ====")
        utils.print_header(self.header, constants.FVE_METADATA_HEADER)

    def __str__(self):
        encryption = constants.ENCRYPTION_METHODS[utils.le_decode_uint8(self.header[36:38])]
        win_time = utils.le_decode_uint64(self.header[40:48])
        created = datetime.utcfromtimestamp(utils.filetime_to_unixtime(win_time))

        s = "Encryption method:\t%s\n" % encryption
        s += "Volume identifier:\t%s\n" % self.guid
        s += "Creation time:\t\t%s\n" % created

        for entry in self._entries:
            s += str(entry)

        return s

    @property
    def block_header(self):
        if not self._metadata_block_headers:
            self._parse()

        return self._metadata_block_headers[0]

    @property
    def header(self):
        if not self._metadata_headers:
            self._parse()

        return self._metadata_headers[0]

    @property
    def guid(self):
        if not self._guid:
            self._guid = utils.le_decode_uuid(self.header[16:32])

        return self._guid

    @property
    def vmks(self):
        vmks = []

        for entry in self._entries:
            if entry.is_vmk:
                vmks.append(entry.vmk)

        if not vmks:
            raise RuntimeError("No VMK entries found in this FVE header")

        return vmks

    @property
    def fvek(self):
        for entry in self._entries:
            if entry.is_fvek:
                return entry.fvek

        raise RuntimeError("No FVEK entry found in this FVE header")

    @property
    def volume_header_block(self):
        for entry in self._entries:
            if entry.is_volume_header:
                return entry

        raise RuntimeError("No Volume header block entry found in this FVE header")

    def get_fvek_by_passphrase(self, password):
        # get the VMK protected by password and calculate VMK key from it
        pw_vmk = next(v for v in self.vmks if v.is_password_protected)
        if pw_vmk is None:
            raise FVEException("No password protected VMKs found.")

        pw_vmk_key = utils.get_key_from_password(password, pw_vmk.salt)

        # decrypt the VMK
        suite = AES.new(pw_vmk_key, AES.MODE_CCM, pw_vmk.aes_key.raw_nonce)

        try:
            decrypted_data = suite.decrypt_and_verify(pw_vmk.aes_key.key,
                                                      received_mac_tag=pw_vmk.aes_key.mac_tag)
            vmk_open_key = UnecryptedKey(decrypted_data)
        except ValueError as e:
            raise FVEException("Failed to decrypt password protected VMK: %s" % str(e)) from e

        # and use it to decrypt the FVEK
        suite = AES.new(vmk_open_key.key, AES.MODE_CCM, self.fvek.raw_nonce)
        decrypted_data = suite.decrypt_and_verify(self.fvek.key,
                                                  received_mac_tag=self.fvek.mac_tag)

        return UnecryptedKey(decrypted_data)
