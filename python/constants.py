PASSWORD = "anaconda"
RECOVERY = "311696-372504-136620-529738-639144-494142-110297-708851"


FVE_METADATA_BLOCK_HEADER_OFFSETS = (176, 184, 192)
FVE_METADATA_BLOCK_HEADER_OFFSET_LEN = 8

FVE_METADATA_BLOCK_HEADER_LEN = 64

FVE_METADATA_BLOCK_OFFSETS = (32, 40, 48)
FVE_METADATA_BLOCK_OFFSET_LEN = 8

FVE_METADATA_HEADER_LEN = 48


ENCRYPTION_METHODS = {0x8000: "AES-CBC 128-bit encryption with Elephant Diffuser",
                      0x8001: "AES-CBC 256-bit encryption with Elephant Diffuser",
                      0x8002: "AES-CBC 128-bit encryption",
                      0x8003: "AES-CBC 256-bit encryption",
                      0x8004: "AES-XTS 128-bit encryption"}


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


KEY_PROTECTION_TYPES = {0x0000: "VMK protected with clear key",
                        0x0100: "VMK protected with TPM",
                        0x0200: "VMK protected with startup key",
                        0x0500: "VMK protected with TPM and PIN",
                        0x0800: "VMK protected with recovery password",
                        0x2000: "VMK protected with password"}
