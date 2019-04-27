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
    return struct.unpack("<Q", data)[0]


def le_decode_uint32(data):
    return struct.unpack("<L", data)[0]


def le_decode_uint16(data):
    return struct.unpack("<I", data)[0]


def le_decode_uint8(data):
    return struct.unpack("<H", data)[0]


def le_decode_uuid(data):
    return str(uuid.UUID(bytes_le=data))


def filetime_to_unixtime(ft):
    return (ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS


def bytes_as_hex(data):
    return " ".join('{:02x}'.format(x) for x in data)


def bytes_decode(data):
    return "'%s'" % data.decode("utf-8", errors="ignore")


def bytes_as_hex_dmsetup(data):
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
    for item in header_type:
        item_data = data[item[0]:(item[0] + item[1])]

        print("\033[1m%s:\033[0m %s %s" % (item[2], bytes_as_hex(item_data), bytes_decode(item_data)))


# misc
def read_from_device(path, start, count):
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(count)

    return data


def run_command(command):
    res = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

    out, err = res.communicate()
    if res.returncode != 0:
        output = out.decode().strip() + "\n\n" + err.decode().strip()
    else:
        output = out.decode().strip()
    return (res.returncode, output)


# passphrase
def sha256(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()


def get_key_from_password(password, salt):
    # initial values
    last_sha256 = b"\x00" * 32
    initial_sha256 = b"\x00" * 32
    salt = salt
    count = 0

    # encode password and cut first two bytes from the password (utf-16 byte-order mark)
    enc_pw = password.encode("utf-16")[2:]

    # initial sha256 -- sha256 of sha256 of the password
    pw_sha256 = sha256(enc_pw)
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
