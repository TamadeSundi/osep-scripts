function EnumerationLocal {
    Write-Host '[*] whoami /all'
    whoami /all

    Write-Host '[*] Language Mode'
    Write-Host $ExecutionContext.SessionState.LanguageMode

    Write-Host '[*] Computer Name'
    Write-Host $env:COMPUTERNAME

    Write-Host '[*] App Locker Rules'
    Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | Format-List

    $result = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
    if ($result.PSObject.Properties.Name -Contains 'RunAsPPL') {
        Write-Host '[*] LSA Protection Policy found'
        $result | Select-Object RunAsPPL | Format-Table
    } else {
        Write-Host '[+] LSA Protection is not enabled!'
    }

    $result = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    if ($result.PSObject.Properties.Name -Contains 'TamperProtection') {
        Write-Host '[*] Tamper Protection Policy found'
        $result | Select-Object TamperProtection | Format-Table
        if (($result | Select-Object -ExpandProperty TamperProtection) -Eq 5) {
            Write-Host '[-] Seems Tamper Protection is enabled ...'
        } else {
            Write-Host '[+] Maybe Tamper Protection is not enabled!'
        }
    } else {
        Write-Host '[+] Tamper Protection is not enabled!'
    }

    Write-Host '[*] Running Processes'
    Get-Process | Select-Object Id, ProcessName, Description, Path | Format-Table

    Write-Host '[*] TCP Listening IPv4 Ports'
    $tcpOpens = Get-NetTCPConnection -State Listen | Where-Object { $_.RemoteAddress -ne '::' } | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object -Property LocalPort
    $tcpOpens | ForEach-Object { $_ | Add-Member NoteProperty 'ProcessName' (Get-Process -Pid $_.OwningProcess | Select-Object -ExpandProperty ProcessName) }
    $tcpOpens | Format-Table

    $usersDirectory = Get-ChildItem -Path C:\Users
    Write-Host '[*] C:\Users Directory Listing'
    $usersDirectory | Format-Table

    $users = $usersDirectory | Select-Object -ExpandProperty Name

    ForEach ($user in $users) {
        $history = "C:\Users\${user}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        try {
            $content = Get-Content -Path $history -ErrorAction Stop
            Write-Host "[+] The user `"${user}`"'s history found!"
            Write-Host "Get-Content -Path ${history}"
            Write-Host '----------------'
            $content
            Write-Host '----------------'
        } catch {
            if ($_.Exception.Message -Eq 'Access is denied') {
                Write-Host "[-] Access Denied for the user `"${user}`"'s path"
            } else {
                Write-Host "[*] The user `"${user}`"'s history not found"
            }
        }
    }

    Write-Host '[*] Interesting items under C:\Users'
    Get-ChildItem -Path C:\Users -Include *.xml,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log,*.key -File -Recurse -ErrorAction SilentlyContinue | Format-Table

    $interestingDirs = 'C:\Program Files', 'C:\Program Files (x86)'
    ForEach ($directory in $interestingDirs) {
        Write-Host "[*] List of ${directory}"
        Get-ChildItem -Path $directory | Format-Table
    }
}

EnumerationLocal