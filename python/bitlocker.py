import argparse
import getpass
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import AES
from datetime import datetime

import constants
import headers
import utils


IMAGE = "../data/image1.raw"


class VMK():
    """Object representing BitLocker VMK"""

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
        for entry in self._entries:
            if entry.is_stretch_key:
                return entry.salt

        raise RuntimeError("No salt for this VMK")

    @property
    def aes_key(self):
        for entry in self._entries:
            if entry.is_aes_key:
                return entry.aes_key

        raise RuntimeError("No key for this VMK")


class AESEncryptedKey():
    """Object representing AES encrypted key in a metadata entry"""

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
    """Object representing BitLocker FVEK"""

    def __str__(self):
        s = "\033[1mFVEK\033[0m\n"
        s += super().__str__()

        return s


class UnecryptedKey():
    def __init__(self, raw_data):
        self.raw_data = raw_data

        self.size = utils.le_decode_uint32(self.raw_data[0:4])
        self.key = self.raw_data[12:]

    def __str__(self):
        encryption = constants.ENCRYPTION_METHODS[utils.le_decode_uint8(self.raw_data[8:10])]

        s = "\033[1mUnecrypted key\033[0m\n"
        s += "\tEncryption method:\t%s\n" % encryption
        s += "\tKey:\t %s\n" % utils.bytes_as_hex(self.key)

        return s


class MetadataEntry():
    """Object representing BitLocker metadata entry"""

    def __init__(self, raw_data):
        self.raw_data = raw_data

        self.entry_header = raw_data[0:8]
        self.entry_data = raw_data[8:]

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
        s = "Metadata entry:"
        s += "\tType: %s" % constants.FVE_ENTRY_TYPES[self.type]
        s += "\tValue: %s" % constants.FVE_VALUE_TYPES[self.value]

        print(s)

    @property
    def vmk(self):
        if not self.is_vmk:
            return None

        if self._vmk is None:
            self._vmk = VMK(self.entry_data)

        return self._vmk

    @property
    def fvek(self):
        if not self.is_fvek:
            return None

        if self._fvek is None:
            self._fvek = FVEK(self.entry_data)

        return self._fvek

    @property
    def aes_key(self):
        if not self.is_aes_key:
            return None

        if self._aes_key is None:
            self._aes_key = AESEncryptedKey(self.entry_data)

        return self._aes_key

    @property
    def description(self):
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


def print_header(data, header_type):
    for item in header_type:
        item_data = data[item[0]:(item[0] + item[1])]

        print("\033[1m%s:\033[0m %s %s" % (item[2], utils.bytes_as_hex(item_data), utils.bytes_decode(item_data)))


def _print_info_from_fve_header(fve_header):
    encryption = constants.ENCRYPTION_METHODS[utils.le_decode_uint8(fve_header[36:38])]
    guid = utils.le_decode_uuid(fve_header[16:32])
    win_time = utils.le_decode_uint64(fve_header[40:48])
    created = datetime.utcfromtimestamp(utils.filetime_to_unixtime(win_time))

    print("Encryption method:\t%s" % encryption)
    print("Volume identifier:\t%s" % guid)
    print("Creation time:\t\t%s" % created)


class FVE():
    """Object representing BitLocker FVE headers"""

    def __init__(self, raw_data):
        self.raw_data = raw_data

        self._metadata_block_headers = []
        self._metadata_headers = []
        self._metadata_starts = []

        self._entries = []

        self._metadata_size = 0

        self._parse()

    def _parse(self):
        self._parse_headers()
        self._verify_headers()
        self._get_metadata_entries()

    def _parse_headers(self):
        # there actually three copies of the FVE, just go throught all of them
        for offset in constants.FVE_METADATA_BLOCK_HEADER_OFFSETS:
            decoded_offset = utils.le_decode_uint64(self.raw_data[offset:(offset + constants.FVE_METADATA_BLOCK_HEADER_OFFSET_LEN)])

            block_header_start = decoded_offset
            block_header_end = decoded_offset + constants.FVE_METADATA_BLOCK_HEADER_LEN
            self._metadata_block_headers.append(self.raw_data[block_header_start:block_header_end])

            metadata_header_start = block_header_end
            metadata_header_end = metadata_header_start + constants.FVE_METADATA_HEADER_LEN
            self._metadata_headers.append(self.raw_data[metadata_header_start:metadata_header_end])

            self._metadata_starts.append(block_header_start)

        self._metadata_size = utils.le_decode_uint32(self.header[0:4])

    def _verify_headers(self):
        # we have three headers, just make sure all of them are the same
        if not all(m == self._metadata_block_headers[0] for m in self._metadata_block_headers):
            raise RuntimeError("FVE metadata block headers mismatch")

        if not all(m == self._metadata_headers[0] for m in self._metadata_headers):
            raise RuntimeError("FVE metadata headers mismatch")

    def _get_metadata_entries(self):
        # metadata entries just start after every FVE header and ends at start of
        # the next one
        start = self._metadata_starts[0] + constants.FVE_METADATA_BLOCK_HEADER_LEN + constants.FVE_METADATA_HEADER_LEN
        end = self._metadata_starts[0] + constants.FVE_METADATA_BLOCK_HEADER_LEN + constants.FVE_METADATA_HEADER_LEN + self._metadata_size

        # we don't know how many entries there are, so just read until there is
        # at least two bytes to read (entry lenght)
        while (end - start) > 2:
            metadata_entry_len = utils.le_decode_uint8(self.raw_data[start:(start + 2)])

            # no more entries
            if metadata_entry_len == 0:
                break

            entry = MetadataEntry(self.raw_data[start:(start + metadata_entry_len)])
            self._entries.append(entry)

            start += metadata_entry_len

    def debug_print(self):
        print("==== FVE metadata block header ====")
        print_header(self.block_header, headers.FVE_METADATA_BLOCK_HEADER)

        print("==== FVE metadata header ====")
        print_header(self.header, headers.FVE_METADATA_HEADER)

    def __str__(self):
        encryption = constants.ENCRYPTION_METHODS[utils.le_decode_uint8(self.header[36:38])]
        guid = utils.le_decode_uuid(self.header[16:32])
        win_time = utils.le_decode_uint64(self.header[40:48])
        created = datetime.utcfromtimestamp(utils.filetime_to_unixtime(win_time))

        s = "Encryption method:\t%s\n" % encryption
        s += "Volume identifier:\t%s\n" % guid
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


def _decrypt_and_save_image(fve, debug, data, fvek_open_key, res_dir):
    # first data block
    first_block = fve.volume_header_block
    data_block = data[first_block.data_offset:(first_block.data_offset + constants.SECTOR_SIZE)]

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
    decrypted_header = _decrypt_data(fvek_open_key.key,
                                     data[first_block.data_offset:(first_block.data_offset + first_block.block_size)],
                                     first_block.data_offset)

    # decrypt everything
    decrypted_everything = _decrypt_data(fvek_open_key.key, data[8192:], 8192)

    # now replace bitlocker metadata with zeroes
    # - 64k after each fve header start
    # - 8k after the encrypted NTFS header start
    for metadata in fve._metadata_starts:
        for i in range(64 * 1024):
            decrypted_everything[metadata + i - 8192] = 0x00

    for i in range(8 * 1024):
        decrypted_everything[fve.volume_header_block.data_offset + i - 8192] = 0x00

    # write the decrypted file
    with open(os.path.join(res_dir, "decrypted.raw"), "wb+") as f:
        f.write(bytes(decrypted_header))
        f.write(bytes(decrypted_everything))

    print("Decrypted image saved to '%s'." % os.path.join(res_dir, "decrypted.raw"))


def main(device, debug, password):
    data = utils.read_image(device)

    fve = FVE(data)
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

    res_dir = os.path.dirname(os.path.realpath(device))
    _decrypt_and_save_image(fve, debug, data, fvek_open_key, res_dir)


if __name__ == '__main__':

    argparser = argparse.ArgumentParser()
    argparser.add_argument("device", help="device (or image) to unlock")
    argparser.add_argument("-v", "--verbose", dest="verbose", help="enable debug messages",
                           action="store_true")
    args = argparser.parse_args()

    if not os.path.exists(args.device):
        print("Device '%s' doesn't exist." % args.device, file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass(prompt="Password for '%s': " % args.device)

    main(device=args.device, debug=args.verbose, password=password)
