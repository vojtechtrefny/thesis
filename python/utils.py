import hashlib
import struct
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


# misc
def read_image(image):
    with open(image, "rb") as f:
        data = f.read()

    return data


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
