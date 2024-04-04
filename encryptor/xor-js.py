#!/usr/bin/env python3
import sys
from typing import NoReturn

def exit_err() -> NoReturn:
    print(f"error: while reading line from stdin: {sys.exc_info()[0]}", file=sys.stderr)
    exit(1)


def print_encrypted() -> None:
    print(f"var buf = [{', '.join([hex(i) for i in encrypted])}];")


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
