# -*- coding: utf-8 -*-
# dm.py
# Device Mapper
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


def create_dm_device(fve, device, fvek_open_key, mapper_name):
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
        raise RuntimeError("Failed to create device mapper device: %s" % out)

    print("Created device mapper device '/dev/mapper/%s'." % mapper_name)
