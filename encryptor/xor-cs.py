#!/usr/bin/env python3
import sys
import re
from typing import NoReturn

def exit_err() -> NoReturn:
    print(f"error: while reading line from stdin: {sys.exc_info()[0]}", file=sys.stderr)
    exit(1)


def print_encrypted() -> None:
    result = ', '.join(map(hex, encrypted))
    print(f"""\
byte[] buf = new byte[{len(encrypted)}] {{ {result} }};
uint[] array = {{ 0x85, 0x39, 0xfc, 0x77, 0x91, 0xcd }};
for(int i = 0; i < buf.Length; i++)
{{
    buf[i] = (byte)((uint)buf[i] ^ array[i % array.Length]);
}}\
""", end='')


def get_line() -> str:
    try:
        line = input().strip()
    except (EOFError, KeyboardInterrupt):
        print_encrypted()
        exit(0)
    except:
        exit_err()

    return line


def xor() -> None:
    hex_patt = re.compile(r'0x[0-9a-fA-F]{2}')
    i = 0
    array = [0x85, 0x39, 0xfc, 0x77, 0x91, 0xcd]
    while True:
        line = get_line()
        for byte in hex_patt.findall(line):
            encrypted.append(int(byte, 16) ^ array[i % len(array)])
            i += 1


def main() -> None:
    xor()

if __name__ == "__main__":
    encrypted = []
    main()
