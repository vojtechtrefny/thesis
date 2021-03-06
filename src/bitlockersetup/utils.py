# -*- coding: utf-8 -*-
# utils.py
# Various utils
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

import hashlib
import struct
import subprocess
import uuid


# http://support.microsoft.com/kb/167296
# How To Convert a UNIX time_t to a Win32 FILETIME or SYSTEMTIME
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


# decode functions
def le_decode_uint64(data):
    """
    Decode 64bit unsigned integer saved in the Little Endian format

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: int
    """
    return struct.unpack("<Q", data)[0]


def le_decode_uint32(data):
    """
    Decode 324bit unsigned integer saved in the Little Endian format

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: int
    """
    return struct.unpack("<L", data)[0]


def le_decode_uint16(data):
    """
    Decode 16bit unsigned integer saved in the Little Endian format

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: int
    """
    return struct.unpack("<I", data)[0]


def le_decode_uint8(data):
    """
    Decode 8bit unsigned integer saved in the Little Endian format

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: int
    """
    return struct.unpack("<H", data)[0]


def le_decode_uuid(data):
    """
    Decode UUID saved in the Little Endian format

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: string
    """
    return str(uuid.UUID(bytes_le=data))


def filetime_to_unixtime(ft):
    """
    Convert Microsoft FILETIME format to UNIXTIME

    :param ft: filetime
    :type ft: int
    :rtype: int
    """
    return (ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS


def bytes_as_hex(data):
    """
    Parse bytes as a hexademical value for printing or debugging purposes

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: string
    """
    return " ".join('{:02x}'.format(x) for x in data)


def bytes_decode(data):
    """
    Parse bytes as a UTF-8 string, ignoring unsupported characters

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: string
    """
    return "'%s'" % data.decode("utf-8", errors="ignore")


def bytes_as_hex_dmsetup(data):
    """
    Parse bytes as a hexademical value for dmsetup

    :param data: raw data read from the disk
    :type data: bytes
    :rtype: string
    """
    return "".join('{:02x}'.format(x) for x in data)


# print
def _decode_and_replace(data):
    result = ""
    chunks = [data[x:x + 1] for x in range(0, len(data), 1)]
    for chunk in chunks:
        try:
            decoded = chunk.decode("ascii")
        except UnicodeDecodeError:
            result += "."
        else:
            if not decoded.isprintable():
                result += "."
            else:
                result += decoded
    return result


def pprint_bytes(data):
    """
    Print bytes in a hexdump-like format

    :param data: raw data read from the disk
    :type data: bytes
    """
    chunks = [data[x:x + 16] for x in range(0, len(data), 16)]
    for i, chunk in enumerate(chunks):
        index = '{:08x}'.format(i * 16)
        ashex = bytes_as_hex(chunk)
        decoded = _decode_and_replace(chunk)

        # add spaces for shorter lines
        if len(ashex) < 48:
            ashex += " " * (48 - len(ashex))
        if len(decoded) < 16:
            decoded += " " * (16 - len(decoded))

        print("%s: %s %s |%s%s|" % (index, ashex[:23], ashex[23:], decoded[:8], decoded[8:]))


def print_header(data, header_type):
    """
    Helper function for printing a metadata header

    :param data: raw data read from the disk
    :type data: bytes
    :param header_type: type of the header
    :type header_type: :func:`~bitlockersetup.constants.BDE_HEADER` or
                       :func:`~bitlockersetup.constants.FVE_METADATA_BLOCK_HEADER` or
                       :func:`~bitlockersetup.constants.FVE_METADATA_HEADER` or
                       :func:`~bitlockersetup.constants.FVE_METADATA_ENTRY`
    """
    for item in header_type:
        item_data = data[item[0]:(item[0] + item[1])]

        print("\033[1m%s:\033[0m %s %s" % (item[2], bytes_as_hex(item_data), bytes_decode(item_data)))


# misc
def read_from_device(path, start, count):
    """
    Read data from a device

    :param path: device path
    :type data: string
    :param start: starting offset for reading
    :type start: int
    :param count: lenght of data to read
    :type count: int
    :rtype: bytes
    """

    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(count)

    return data


def run_command(command):
    """
    Run a command in shell

    :param command: shell command
    :type command: string
    :returns: return code and output (including error output)
    :rtype: tuple of int and string
    """
    res = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

    out, err = res.communicate()
    if res.returncode != 0:
        output = out.decode().strip() + "\n\n" + err.decode().strip()
    else:
        output = out.decode().strip()
    return (res.returncode, output)


def read_file(fname):
    content = ""
    with open(fname, "r") as f:
        content = f.read().decode().strip()

    return content


# passphrase
def get_passphrase_from_recovery(recovery_password):
    # first split into parts and convert to int
    parts = recovery_password.split("-")
    parts = [int(p) for p in parts]

    # check everything is divisible by 11
    if not all((p % 11 == 0 for p in parts)):
        raise ValueError("Recovery password is not valid.")

    # now divide parts by 11
    parts = [p // 11 for p in parts]

    # and convert all parts to 2 B little endian values
    parts = [p.to_bytes(2, "little") for p in parts]

    # return final value -- joined 16 B (128 bit) recovery "key"
    return b"".join(parts)


def sha256(data):
    """
    Calculate SHA256 hash

    :param data: data to hash
    :type data: bytes
    :rtype: string
    """
    m = hashlib.sha256()
    m.update(data)
    return m.digest()


def get_key_from_password(password, salt, recovery=False):
    """
    Derivate key from a password. Uses BitLocker custom KDF.

    .. note:: This function runs SHA256 1048576 times in a loop so this can
              take some time on slower PCs.

    :param password: password from user input
    :type password: bytes
    :param salt: salt from VMK protected using this password
    :type salt: bytes
    :param recovery: whether we are working with recovery password or not
    :type recovery: bool
    :returns: derived key
    :rtype: bytes
    """

    # initial values
    last_sha256 = b"\x00" * 32
    initial_sha256 = b"\x00" * 32
    salt = salt
    count = 0

    # initial sha256
    pw_sha256 = sha256(password)
    if recovery:
        # nothing to do here, one sha256 is enough for recovery password
        initial_sha256 = pw_sha256
    else:
        # we need to do one extra sha256 for the "normal" password
        initial_sha256 = sha256(pw_sha256)


    # initial settings done, let's pack it in the "struct"
    data = last_sha256 + initial_sha256 + salt + (count).to_bytes(8, "little")

    for _ in range(1048576):
        # update last_sha256 to sha256 of the struct and increase the counter
        last_sha256 = sha256(data)
        count += 1

        # and repack the "struct"
        data = last_sha256 + initial_sha256 + salt + (count).to_bytes(8, "little")

    return last_sha256
