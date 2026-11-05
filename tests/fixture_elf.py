"""A real synthetic x86-64 Linux executable, with no files or external runtime."""
import struct


def synthetic_core():
    code = bytes.fromhex("31 ff b8 3c 00 00 00 0f 05")  # exit(0)
    base = 0x400000
    text = 64 + 56
    length = text + len(code)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    elf = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, base + text,
                      64, 0, 0, 64, 56, 1, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, length, length, 4096)
    return elf + load + code
