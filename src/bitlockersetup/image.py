# -*- coding: utf-8 -*-
# image.py
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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from bitlockersetup import constants, utils


def _decrypt_data(key, data, iv_offset, cipher):
    decrypted = bytearray()

    sectors = int(len(data) / constants.SECTOR_SIZE)

    for i in range(sectors):
        if cipher == constants.Ciphers.AES_CBC:
            # IV = ECB encrypted offset in bytes
            iv = (iv_offset + i * constants.SECTOR_SIZE).to_bytes(16, "little")

            iv_cipher = Cipher(algorithms.AES(key), modes.ECB(),
                               backend=default_backend())
            encryptor = iv_cipher.encryptor()
            iv = encryptor.update(iv) + encryptor.finalize()

            mode_fn = modes.CBC
        elif cipher == constants.Ciphers.AES_XTS:
            # IV = offset in sectors
            iv = (int(iv_offset / constants.SECTOR_SIZE) + i).to_bytes(16, "little")
            mode_fn = modes.XTS

        data_cipher = Cipher(algorithms.AES(key), mode_fn(iv),
                             backend=default_backend())
        decryptor = data_cipher.decryptor()
        start = i * constants.SECTOR_SIZE
        end = (i * constants.SECTOR_SIZE) + constants.SECTOR_SIZE
        result = decryptor.update(data[start:end]) + decryptor.finalize()
        decrypted.extend(bytearray(result))

    return decrypted


def _read_and_decrypt_data(device, start, count, key, iv_offset, cipher):
    """ Read the device sector by sector and decrypt it """
    decrypted = bytearray()

    with open(device, "rb") as f:
        f.seek(start)

        for i in range(0, count, constants.SECTOR_SIZE):
            data = f.read(constants.SECTOR_SIZE)
            decrypted_data = _decrypt_data(key, data, iv_offset + i, cipher)
            decrypted.extend(bytearray(decrypted_data))

    return decrypted


def decrypt_and_save_image(fve, debug, device, fvek_open_key, res_file, cipher=constants.Ciphers.AES_XTS):
    """
    Decrypt entire seleted device and save the data as a raw image

    :param fve: parsed FVE header
    :type fve: :func:`~bitlockersetup.fve.FVE`
    :param device: device path of an existing BitLocker device
    :type device: string
    :param fvek_open_key: decrypted FVEK
    :type fvek_open_key: string
    :res_file: name for the file to save the data to
    :res_file: string
    """

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
                                   first_block.data_offset,
                                   cipher)

    if debug:
        print("\033[1mFirst sector (decrypted):\033[0m")
        utils.pprint_bytes(decrypted_data)

    # decrypt whole "header" part
    header_data = utils.read_from_device(device,
                                         first_block.data_offset,
                                         first_block.block_size)
    decrypted_header = _decrypt_data(fvek_open_key.key,
                                     header_data,
                                     first_block.data_offset,
                                     cipher)

    # decrypt everything
    decrypted_everything = _read_and_decrypt_data(device, 8192,
                                                  fve._device_size - 8192,
                                                  fvek_open_key.key, 8192,
                                                  cipher)

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
