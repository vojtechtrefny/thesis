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
    """
    Object representing BitLocker FVE headers

    :param device: full path of the BitLocker device
    :type device: string
    :param bde_header: BitLocker header
    :type bde_header: :func:`~bitlockersetup.header.BitLockerHeader`
    """

    def __init__(self, device, bde_header):

        self.device = device
        self.bde_header = bde_header

        self._metadata_block_headers = []
        self._metadata_headers = []
        self._metadata_starts = []

        self._entries = []

        self._metadata_size = 0
        self._device_size = 0

        self._encryption_type = 0

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
        """
        Prints all information in this header for debugging purposes
        """

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
        """
        FVE block header

        :rtype: bytes
        """
        if not self._metadata_block_headers:
            self._parse()

        return self._metadata_block_headers[0]

    @property
    def header(self):
        """
        FVE header

        :rtype: bytes
        """
        if not self._metadata_headers:
            self._parse()

        return self._metadata_headers[0]

    @property
    def guid(self):
        """
        GUID of the device

        :rtype: string
        """
        if not self._guid:
            self._guid = utils.le_decode_uuid(self.header[16:32])

        return self._guid

    @property
    def vmks(self):
        """
        List of Volume Master Keys found in this FVE metadata

        :rtype: list of :func:`~bitlockersetup.keys.VMK`
        """
        vmks = []

        for entry in self._entries:
            if entry.is_vmk:
                vmks.append(entry.vmk)

        if not vmks:
            raise RuntimeError("No VMK entries found in this FVE header")

        return vmks

    @property
    def fvek(self):
        """
        Encrypted Full Volume Encryption Key found in this FVE metadata

        :rtype: :func:`~bitlockersetup.keys.FVEK`
        """
        for entry in self._entries:
            if entry.is_fvek:
                return entry.fvek

        raise RuntimeError("No FVEK entry found in this FVE header")

    @property
    def volume_header_block(self):
        """
        Metadata Entry containing Volume Header Block

        :rtype: :func:`~bitlockersetup.entry.MetadataEntry`
        """
        for entry in self._entries:
            if entry.is_volume_header:
                return entry

        raise RuntimeError("No Volume header block entry found in this FVE header")

    @property
    def encryption_type(self):
        """
        Type of encryption used for data encryption

        :rtype: :func:`~constants.ENCRYPTION_METHODS`
        """

        if not self._encryption_type:
            self._encryption_type = utils.le_decode_uint8(self.header[36:38])

        return self._encryption_type

    def _get_fvek_by_vmk(self, vmk, vmk_key):
        # decrypt the VMK
        suite = AES.new(vmk_key, AES.MODE_CCM, vmk.aes_key.raw_nonce)

        try:
            decrypted_data = suite.decrypt_and_verify(vmk.aes_key.key,
                                                      received_mac_tag=vmk.aes_key.mac_tag)
            vmk_open_key = UnecryptedKey(decrypted_data)
        except ValueError as e:
            raise FVEException("Failed to decrypt VMK: %s" % str(e)) from e

        # and use it to decrypt the FVEK
        suite = AES.new(vmk_open_key.key, AES.MODE_CCM, self.fvek.raw_nonce)
        decrypted_data = suite.decrypt_and_verify(self.fvek.key,
                                                  received_mac_tag=self.fvek.mac_tag)

        return UnecryptedKey(decrypted_data)


    def get_fvek_by_passphrase(self, password):
        """
        Extract decrypted FVEK using a password protected VMK

        :param password: password
        :type password: string

        :rtype: :func:`~bitlockersetup.keys.UnecryptedKey`
        """
        # get the VMK protected by password and calculate VMK key from it
        pw_vmk = next(v for v in self.vmks if v.is_password_protected)
        if pw_vmk is None:
            raise FVEException("No password protected VMKs found.")

        # encode password and cut first two bytes from the password (utf-16 byte-order mark)
        password = password.encode("utf-16")[2:]

        # and now derive the key for decrypting VMK from the password
        vmk_key = utils.get_key_from_password(password, pw_vmk.salt, recovery=False)

        return self._get_fvek_by_vmk(pw_vmk, vmk_key)

    def get_fvek_by_recovery_passphrase(self, recovery_password):
        """
        Extract decrypted FVEK using a recovery password protected VMK

        :param password: recovery password
        :type password: string

        :rtype: :func:`~bitlockersetup.keys.UnecryptedKey`
        """
        # get the VMK protected by password and calculate VMK key from it
        rpw_vmk = next(v for v in self.vmks if v.is_recovery_protected)
        if rpw_vmk is None:
            raise FVEException("No recovery password protected VMKs found.")

        # get recovery 'key' from the password (split, divide by 11 and join)
        recovery_password = utils.get_passphrase_from_recovery(recovery_password)

        # and now derive the key for decrypting VMK from the recovery password
        vmk_key = utils.get_key_from_password(recovery_password, rpw_vmk.salt, recovery=True)

        return self._get_fvek_by_vmk(rpw_vmk, vmk_key)
