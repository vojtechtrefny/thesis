# -*- coding: utf-8 -*-
# constants.py
# Various constants
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

from enum import Enum


# misc
SECTOR_SIZE = 512

class Ciphers(Enum):
    """
    Ciphers used in BitLocker
    """

    AES_CBC = 1
    AES_XTS = 2


# signature
BD_SIGNATURE = b"\x2d\x46\x56\x45\x2d\x46\x53\x2d"  # -FVE-FS-
BD_TOGO_SIGNATURE = b"\x4d\x53\x57\x49\x4e\x34\x2e\x31"  # MSWIN4.1
BDE_HEADER_SIZE = 512


# offsets
FVE_METADATA_BLOCK_HEADER_OFFSETS = (176, 184, 192)
FVE_METADATA_BLOCK_HEADER_OFFSETS_TOGO = (440, 448, 456)
FVE_METADATA_BLOCK_HEADER_OFFSET_LEN = 8

FVE_METADATA_BLOCK_HEADER_LEN = 64

FVE_METADATA_BLOCK_OFFSETS = (32, 40, 48)
FVE_METADATA_BLOCK_OFFSET_LEN = 8

FVE_METADATA_HEADER_LEN = 48


# encryption algorithms
ENCRYPTION_METHODS = {0x2003: "AES-CCM 128-bit encryption",
                      0x8000: "AES-CBC 128-bit encryption with Elephant Diffuser",
                      0x8001: "AES-CBC 256-bit encryption with Elephant Diffuser",
                      0x8002: "AES-CBC 128-bit encryption",
                      0x8003: "AES-CBC 256-bit encryption",
                      0x8004: "AES-XTS 128-bit encryption"}


# metadata entries
FVE_ENTRY_TYPES = {0x0000: "Property",
                   0x0002: "Volume Master Key (VMK)",
                   0x0003: "Full Volume Encryption Key (FKEV)",
                   0x0004: "Validation",
                   0x0006: "Startup key",
                   0x0007: "Description",
                   0x000b: "Unknown",
                   0x000f: "Volume header block"}


FVE_VALUE_TYPES = {0x0000: "Erased",
                   0x0001: "Key",
                   0x0002: "Unicode string",
                   0x0003: "Stretch Key",
                   0x0004: "Use Key",
                   0x0005: "AES-CCM encrypted key",
                   0x0006: "TPM encoded key",
                   0x0007: "Validation",
                   0x0008: "Volume master key",
                   0x0009: "External key",
                   0x000a: "Update",
                   0x000b: "Error",
                   0x000f: "Offset and size"}


# protectors
KEY_PROTECTION_TYPES = {0x0000: "VMK protected with clear key",
                        0x0100: "VMK protected with TPM",
                        0x0200: "VMK protected with startup key",
                        0x0500: "VMK protected with TPM and PIN",
                        0x0800: "VMK protected with recovery password",
                        0x2000: "VMK protected with password"}


# headers
BDE_HEADER = [(0, 3, "Boot entry point"),
              (3, 8, "File system signature"),
              (11, 2, "Bytes per sector"),
              (13, 1, "Sectors per cluster block"),
              (14, 2, "Reserved Sectors"),
              (16, 1, "Number of File Allocation Tables (FATs)"),
              (17, 2, "Root directory entries"),
              (19, 2, "Total number of sectors (16-bit)"),
              (21, 1, "Media descriptor"),
              (22, 2, "Sectors Per File Allocation Table (FAT)"),
              (24, 2, "Sectors per track"),
              (26, 2, "Number of heads"),
              (28, 4, "Number of hidden sectors"),
              (32, 4, "Total number of sectors (32-bit)"),
              (36, 4, "Sectors per file allocation table"),
              (40, 2, "FAT Flags"),
              (42, 2, "Version (Defined as 0)"),
              (44, 4, "Cluster number of root directory start"),
              (48, 2, "Sector number of FS Information Sector"),
              (50, 2, "Sector number of a copy of this boot sector (0 if no backup copy exists)"),
              (52, 12, "Reserved"),
              (64, 1, "Physical Drive Number"),
              (65, 1, "Reserved"),
              (66, 1, "Extended boot signature"),
              (67, 4, "Volume serial number"),
              (71, 11, "Volume label"),
              (82, 8, "File system signature"),
              (90, 70, "Bootcode"),
              (160, 16, "BitLocker identifier (GUID)"),
              (176, 8, "FVE metadata block 1 offset"),
              (184, 8, "FVE metadata block 2 offset"),
              (192, 8, "FVE metadata block 3 offset"),
              (200, 307, "Unknown (part of bootcode)"),
              (507, 3, "Unknown"),
              (510, 2, "Sector signature")]


FVE_METADATA_BLOCK_HEADER = [(0, 8, "Signature"),
                             (8, 2, "Size"),
                             (10, 2, "Version"),
                             (12, 2, "Unknown"),
                             (14, 2, "Unknown copy"),
                             (16, 8, "Encrypted volume size (bytes)"),
                             (24, 4, "Unknown"),
                             (28, 4, "Number of volume header sectors"),
                             (32, 8, "FVE metadata block 1 offset"),
                             (40, 8, "FVE metadata block 2 offset"),
                             (48, 8, "FVE metadata block 3 offset"),
                             (56, 8, "Volume header offset")]


FVE_METADATA_HEADER = [(0, 4, "Metadata size"),
                       (4, 4, "Version"),
                       (8, 4, "Metadata header size"),
                       (12, 4, "Metadata size copy"),
                       (16, 16, "Volume identifier (GUID)"),
                       (32, 4, "Next nonce counter"),
                       (36, 4, "Encryption method"),
                       (40, 8, "Creation time (FILETIME)")]


FVE_METADATA_ENTRY = [(0, 2, "Entry size"),
                      (2, 2, "Entry type"),
                      (4, 2, "Value type"),
                      (6, 2, "Version")]
