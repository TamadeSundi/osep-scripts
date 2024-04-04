#!/bin/bash

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <plain text>\n' "$1" 2>&1
    exit 1
fi

# https://blog.atucom.net/2012/10/generate-ntlm-hashes-via-command-line.html
iconv -f ASCII -t UTF-16LE <(printf "$1") | openssl dgst -md4 | cut -d\  -f2
