#!/usr/bin/env python3
import sys
import re
from typing import NoReturn

def exit_err() -> NoReturn:
    print(f"error: while reading line from stdin: {sys.exc_info()[0]}", file=sys.stderr)
    exit(1)


def print_encrypted() -> None:
    result = ''.join(map(lambda x: f"\\{hex(x)[1:]}", encrypted))
    print(f"""\
#include <sys/mman.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>

unsigned char buf[] =
"{result}";
unsigned char array[] = "\\x85\\x39\\xfc\\x77\\x91\\xcd";

int main() {{
    if (fork() != 0) {{
        return 0;
    }}

    intptr_t pagesize = sysconf(_SC_PAGESIZE);
    int arr_size = (int)(sizeof(array) / sizeof(unsigned char)) - 1;
    int buf_size = (int)(sizeof(buf) / sizeof(unsigned char)) - 1;
    int i;
    for(i = 0; i < buf_size; i++) {{
        buf[i] = buf[i] ^ array[i % arr_size];
    }}
    if (mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)), pagesize, PROT_READ | PROT_EXEC)) {{
        return 1;
    }}
    int (*ret)() = (int(*)())buf;
    ret();
}}
""")


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
    hex_patt = re.compile(r'(?<=\\x)[0-9a-fA-F]{2}')
    i = 0
    array = [0x85, 0x39, 0xfc, 0x77, 0x91, 0xcd]
    while True:
        line = get_line()
        for byte in hex_patt.findall(line):
            encrypted.append(int(f"0x{byte}", 16) ^ array[i % len(array)])
            i += 1


def main() -> None:
    xor()

if __name__ == "__main__":
    encrypted = []
    main()
