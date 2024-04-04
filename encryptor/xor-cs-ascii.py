#!/usr/bin/env python3
import sys
from typing import NoReturn

def exit_err() -> NoReturn:
    print(f"error: while reading line from stdin: {sys.exc_info()[0]}", file=sys.stderr)
    exit(1)


def print_encrypted() -> None:
    hex_encrypted = [hex(c) for c in bytes(encrypted)]
    print(f"""\
byte[] encrypted = new byte[{len(hex_encrypted)}] {{ {', '.join(hex_encrypted)} }};
uint[] xorCrypto = new uint[6] {{ 0x85, 0x39, 0xfc, 0x77, 0x91, 0xcd }};
for (int i = 0; i < encrypted.Length; i++)
{{
    encrypted[i] = (byte)((uint)encrypted[i] ^ xorCrypto[i % xorCrypto.Length]);
}}
string psScript = System.Text.Encoding.ASCII.GetString(encrypted);\
""")


def xor() -> None:
    array = [0x85, 0x39, 0xfc, 0x77, 0x91, 0xcd]
    data = sys.stdin.buffer.read()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ array[i % len(array)])
    print_encrypted()


def main() -> None:
    xor()

if __name__ == "__main__":
    encrypted = []
    main()
