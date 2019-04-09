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
        self.encryption = utils.le_decode_uint16(self.raw_data[8:12])
        self.key = self.raw_data[12:]

    def __str__(self):
        encryption_str = constants.ENCRYPTION_METHODS[self.encryption]

        s = "\033[1mUnecrypted key\033[0m\n"
        s += "\tEncryption method:\t%s\n" % encryption_str
        s += "\tKey:\t %s\n" % utils.bytes_as_hex(self.key)

        return s


class MetadataEntry():
    """Object representing BitLocker metadata entry"""

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
        s = "Metadata entry:\n"
        s += "\tType: %s\n" % constants.FVE_ENTRY_TYPES[self.type]
        s += "\tValue: %s\n" % constants.FVE_VALUE_TYPES[self.value]

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
        for item in headers.BDE_HEADER:
            item_data = self.raw_data[item[0]:(item[0] + item[1])]

            print("\033[1m%s:\033[0m %s %s" % (item[2], utils.bytes_as_hex(item_data), utils.bytes_decode(item_data)))


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
