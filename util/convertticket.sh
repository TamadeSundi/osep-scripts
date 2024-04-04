#!/bin/bash

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s <kirbi, ccahename>, then paste base64 encoded kirbi (Rubeus dumped) from stdin\n' "$0"
    exit 0
fi

filename="$1"
kirbi="${filename}.kirbi"
ccache="${filename}.ccache"
printf '[*] Pasete your base64 encoded kirbi string.\n'
cat | base64 -d > "$kirbi"
printf '\n[+] %s was created.\n' "$kirbi"
impacket-ticketConverter "$kirbi" "$ccache"
printf '[+] %s was created.\n' "$ccache"
printf 'export KRB5CCNAME=%s/%s' "$(pwd)" "$ccache"
