try {
    Get-Domain | Out-Null
} catch {
    Write-Host '[-] Requirement: PowerView.ps1'
    Return
}

class PowerViewWrapper {
    [Array]$DomainController
    [Array]$DomainUser
    [Array]$DomainGroup
    [Array]$DomainComputer
    [Array]$DomainObject

    [Array]$DomainUserAcl
    [Array]$DomainGroupAcl
    [Array]$DomainComputerAcl
    [Array]$DomainObjectAcl

    [Array]$Unconstrained
    [Array]$ConstrainedUser
    [Array]$ConstrainedComputer
    [Array]$ResourceBasedConstrained

    [Array]$JohnHashes

    [Array]$DomainAdmins
    [Array]$EnterpriseAdmins

    [Array]$LastLoggedOn
    [Array]$CachedRDP

    [PSCredential]$Cred

    PowerViewWrapper() {
        $this.Cred = [PSCredential]::Empty
        $this.DomainController = Get-DomainController
        $this.DomainUser = Get-DomainUser
        $this.DomainGroup = Get-DomainGroup
        $this.DomainComputer = Get-DomainComputer
        $this.DomainObject = Get-DomainObject
        $this.Common()
        $this.Unconstrained = Get-DomainComputer -Unconstrained
        $this.ConstrainedUser = Get-DomainUser -TrustedToAuth
        $this.ConstrainedComputer = Get-DomainComputer -TrustedToAuth
        $this.ResourceBasedConstrained = Get-DomainComputer -LDAPFilter 'msds-allowedtoactionbehalfofotheridentity=*'
        $this.JohnHashes = Invoke-Kerberoast -OutputFormat John | Select-Object SamAccountName, Hash | Foreach-Object { $_.Hash -Match '[^:]+$' | Out-Null; '$krb5tgs$' + $_.SamAccountName + ':' + $matches.Values[0] }
        $this.DomainAdmins = Get-DomainGroupMember -Identity 'Domain Admins'
        $this.EnterpriseAdmins = Get-DomainGroupMember -Identity 'Enterprise Admins'
    }

    PowerViewWrapper([string]$domain) {
        $this.Cred = [PSCredential]::Empty
        $this.DomainController = Get-DomainController -Domain $domain
        $this.DomainUser = Get-DomainUser -Domain $domain
        $this.DomainGroup = Get-DomainGroup -Domain $domain
        $this.DomainComputer = Get-DomainComputer -Domain $domain
        $this.DomainObject = Get-DomainObject -Domain $domain
        $this.Common()
        $this.Unconstrained = Get-DomainComputer -Domain $domain -Unconstrained
        $this.ConstrainedUser = Get-DomainUser -Domain $domain -TrustedToAuth
        $this.ConstrainedComputer = Get-DomainComputer -Domain $domain -TrustedToAuth
        $this.ResourceBasedConstrained = Get-DomainComputer -Domain $domain -LDAPFilter 'msds-allowedtoactionbehalfofotheridentity=*'
        $this.JohnHashes = Invoke-Kerberoast -Domain $domain -OutputFormat John | Select-Object SamAccountName, Hash | Foreach-Object { $_.Hash -Match '[^:]+$' | Out-Null; '$krb5tgs$' + $_.SamAccountName + ':' + $matches.Values[0] }
        $this.DomainAdmins = Get-DomainGroupMember -Domain $domain -Identity 'Domain Admins'
        $this.EnterpriseAdmins = Get-DomainGroupMember -Domain $domain -Identity 'Enterprise Admins'
    }

    PowerViewWrapper([PSCredential]$credential) {
        $this.Cred = $credential
        $this.DomainController = Get-DomainController -Credential $this.Cred
        $this.DomainUser = Get-DomainUser -Credential $this.Cred
        $this.DomainGroup = Get-DomainGroup -Credential $this.Cred
        $this.DomainComputer = Get-DomainComputer -Credential $this.Cred
        $this.DomainObject = Get-DomainObject -Credential $this.Cred
        $this.Common()
        $this.Unconstrained = Get-DomainComputer -Unconstrained -Credential $this.Cred
        $this.ConstrainedUser = Get-DomainUser -TrustedToAuth -Credential $this.Cred
        $this.ConstrainedComputer = Get-DomainComputer -TrustedToAuth -Credential $this.Cred
        $this.ResourceBasedConstrained = Get-DomainComputer -LDAPFilter 'msds-allowedtoactionbehalfofotheridentity=*' -Credential $this.Cred
        $this.JohnHashes = Invoke-Kerberoast -OutputFormat John -Credential $this.Cred | Select-Object SamAccountName, Hash | Foreach-Object { $_.Hash -Match '[^:]+$' | Out-Null; '$krb5tgs$' + $_.SamAccountName + ':' + $matches.Values[0] }
        $this.DomainAdmins = Get-DomainGroupMember -Identity 'Domain Admins' -Credential $this.Cred
        $this.EnterpriseAdmins = Get-DomainGroupMember -Identity 'Enterprise Admins' -Credential $this.Cred
    }

    PowerViewWrapper([string]$domain, [PSCredential]$credential) {
        $this.Cred = $credential
        $this.DomainController = Get-DomainController -Domain $domain -Credential $this.Cred
        $this.DomainUser = Get-DomainUser -Domain $domain -Credential $this.Cred
        $this.DomainGroup = Get-DomainGroup -Domain $domain -Credential $this.Cred
        $this.DomainComputer = Get-DomainComputer -Domain $domain -Credential $this.Cred
        $this.DomainObject = Get-DomainObject -Domain $domain -Credential $this.Cred
        $this.Common()
        $this.Unconstrained = Get-DomainComputer -Domain $domain -Unconstrained -Credential $this.Cred
        $this.ConstrainedUser = Get-DomainUser -Domain $domain -TrustedToAuth -Credential $this.Cred
        $this.ConstrainedComputer = Get-DomainComputer -Domain $domain -TrustedToAuth -Credential $this.Cred
        $this.ResourceBasedConstrained = Get-DomainComputer -Domain $domain -LDAPFilter 'msds-allowedtoactionbehalfofotheridentity=*' -Credential $this.Cred
        $this.JohnHashes = Invoke-Kerberoast -Domain $domain -OutputFormat John -Credential $this.Cred | Select-Object SamAccountName, Hash | Foreach-Object { $_.Hash -Match '[^:]+$' | Out-Null; '$krb5tgs$' + $_.SamAccountName + ':' + $matches.Values[0] }
        $this.DomainAdmins = Get-DomainGroupMember -Domain $domain -Identity 'Domain Admins' -Credential $this.Cred
        $this.EnterpriseAdmins = Get-DomainGroupMember -Domain $domain -Identity 'Enterprise Admins' -Credential $this.Cred
    }

    [void] Common() {
        if ($this.Cred -Ne [PSCredential]::Empty) {
            $this.DomainUserAcl = $this.DomainUser | Get-ObjectAcl -ResolveGUIDs -Credential $this.Cred
            $this.DomainGroupAcl = $this.DomainGroup | Get-ObjectAcl -ResolveGUIDs -Credential $this.Cred
            $this.DomainComputerAcl = $this.DomainComputer | Get-ObjectAcl -ResolveGUIDs -Credential $this.Cred
            $this.LastLoggedOn = $this.DomainComputer | Get-LastLoggedOn -Credential $this.Cred
            $this.CachedRDP = $this.DomainComputer | Get-CachedRDPConnection -Credential $this.Cred
        } else {
            $this.DomainUserAcl = $this.DomainUser | Get-ObjectAcl -ResolveGUIDs
            $this.DomainGroupAcl = $this.DomainGroup | Get-ObjectAcl -ResolveGUIDs
            $this.DomainComputerAcl = $this.DomainComputer | Get-ObjectAcl -ResolveGUIDs
            $this.LastLoggedOn = $this.DomainComputer | Get-LastLoggedOn
            $this.CachedRDP = $this.DomainComputer | Get-CachedRDPConnection
        }
    }

    [Array] EnumWritable([string]$attacker, [string]$target) {
        $objects = 'Users', 'Groups', 'Computers'
        $containers = $this.DomainUser, $this.DomainGroup, $this.DomainComputer
        $acls = $this.DomainUserAcl, $this.DomainGroupAcl, $this.DomainComputerAcl

        if (-Not ($objects -Contains $attacker -And $objects -Contains $target)) {
            throw "Exception: attacker or target is not supported: attacker = ${attacker}, target = ${target}"
        }

        $attackerObject = $containers[$objects.IndexOf(($objects | Where-Object { $_ -Eq $attacker }))]
        $targetObject = $acls[$objects.IndexOf(($objects | Where-Object { $_ -Eq $target }))]

        $result = $targetObject | Where-Object { ($_.ActiveDirectoryRights -Match 'GenericWrite|WriteProperty|WriteDacl|WriteOwner|GenericAll|ExtendedRight|Self') -And ($attackerObject.ObjectSID -Contains $_.SecurityIdentifier.Value) } | Foreach-Object { $_ | Add-Member -NotePropertyName Identity -NotePropertyValue ($attackerObject.SamAccountName[$attackerObject.ObjectSID.IndexOf($_.SecurityIdentifier.Value)]) -Force; $_ }

        Return $result
    }
}

class PowerViewWrapperCommon {
    [Array]$Domains
    [Hashtable]$DomainSIDs
    [Array]$DomainTrustMapping
    [Array]$ExternalUsersAndGroups
    [Array]$Shares

    PowerViewWrapperCommon() {
        $this.DomainTrustMapping = Get-DomainTrustMapping
        $this.Domains = $this.DomainTrustMapping | ForEach-Object { $_.SourceName, $_.TargetName } | Select-Object -Unique

        if ($this.Domains -Eq $null) {
            $this.Domains = Get-Domain | Select-Object -ExpandProperty Name
        }

        $this.ExternalUsersAndGroups = $this.DomainTrustMapping | ForEach-Object { $_.SourceName, $_.TargetName } | Select-Object -Unique | ForEach-Object { "Domain: ${_}"; Get-DomainForeignGroupMember -Domain $_ | Select-Object GroupDomain, MemberDomain, GroupName, MemberName | ForEach-Object { try { $_.MemberName = "User: $(ConvertFrom-SID $_.MemberName)" } catch {}; $_ } } | Format-Table
        $this.Shares = Invoke-ShareFinder

        $this.DomainSIDs = @{}
        foreach ($domain in $this.Domains) {
            $this.DomainSIDs.$domain = Get-DomainSID -Domain $domain
            }
    }

    PowerViewWrapperCommon([PSCredential]$credential) {
        $this.DomainTrustMapping = Get-DomainTrustMapping -Credential $credential
        $this.Domains = $this.DomainTrustMapping | ForEach-Object { $_.SourceName, $_.TargetName } | Select-Object -Unique

        if ($this.Domains -Eq $null) {
            $this.Domains = Get-Domain -Credential $credential | Select-Object -ExpandProperty Name
        }

        $this.ExternalUsersAndGroups = $this.DomainTrustMapping | ForEach-Object { $_.SourceName, $_.TargetName } | Select-Object -Unique | ForEach-Object { "Domain: ${_}"; Get-DomainForeignGroupMember -Domain $_ -Credential $credential | Select-Object GroupDomain, MemberDomain, GroupName, MemberName | ForEach-Object { try { $_.MemberName = "User: $(ConvertFrom-SID $_.MemberName -Credential $credential)" } catch {}; $_ } } | Format-Table
        $this.Shares = Invoke-ShareFinder -Credential $credential

        $this.DomainSIDs = @{}
        foreach ($domain in $this.Domains) {
            $this.DomainSIDs.$domain = Get-DomainSID -Domain $domain -Credential $credential
        }
    }
}

function PrintAbilities {
    param(
        [Parameter(Position = 0, Mandatory = $True)] $currents
    )

    $writable = @()
    $expand = @()
    ForEach ($current in $currents) {
        $temp = New-Object PSObject
        $temp | Add-Member NoteProperty 'Attacker' ($current | Select-Object -ExpandProperty Identity)
        $temp | Add-Member NoteProperty 'Target' ($current | Select-Object -ExpandProperty ObjectDN)
        if ($current.ActiveDirectoryRights -Match 'GenericWrite|WriteProperty|WriteDacl|WriteOwner|GenericAll|Self') {
            $temp | Add-Member NoteProperty 'ActiveDirectoryRights' ($current | Select-Object -ExpandProperty ActiveDirectoryRights)
            $writable += $temp
        } else {
            $temp | Add-Member NoteProperty 'ObjectAceType' ($current | Select-Object -ExpandProperty ObjectAceType)
            $expand += $temp
        }
    }
    if ($writable -Ne @()) {
        $writable | Format-Table
    }
    if ($expand -Ne @()) {
        $expand | Format-Table
    }
}

function ReturnGroupMembers {
    param(
        [Parameter(Position = 0, Mandatory = $True)] $groupName,
        [Parameter(Position = 1, Mandatory = $True)] $members
    )

    $result = @()
    ForEach ($member in $members) {
        $temp = New-Object PSObject
        $temp | Add-Member NoteProperty 'GroupName' $groupName
        $temp | Add-Member NoteProperty 'Member' $member
        $result += $temp
    }
    Return $result
}

function ReturnGroupMemberOfs {
    param(
        [Parameter(Position = 0, Mandatory = $True)] $groupName,
        [Parameter(Position = 1, Mandatory = $True)] $memberOfs
    )

    $result = @()
    ForEach ($memberOf in $memberOfs) {
        $temp = New-Object PSObject
        $temp | Add-Member NoteProperty 'Parent' $MemberOf
        $temp | Add-Member NoteProperty 'GroupName' $groupName
        $result += $temp
    }
    Return $result
}

function Enum-AD {
    param(
        [Parameter(Position = 0, Mandatory = $False)] [string]$User = "",
        [Parameter(Position = 1, Mandatory = $False)] [string]$Pass = ""
    )

    $cred = [PSCredential]::Empty
    if ((-Not [string]::IsNullOrEmpty($User)) -And (-Not [string]::IsNullOrEmpty($Pass))) {
        $Pass = ConvertTo-SecureString "$Pass" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($User, $Pass)
    }

    $wellKnownUsers = 'Administrator', 'Guest', 'krbtgt'
    $wellKnownLocalGroups = 'Terminal Server License Servers', 'Administrators', 'Account Operators'
    $wellKnownDomainGroups = 'Domain Computers', 'Domain Controllers', 'Schema Admins', 'Enterprise Admins', 'Cert Publishers', 'Domain Admins', 'Domain Users', 'Domain Guests', 'Group Policy Creator Owners', 'RAS and IAS Servers', 'Allowed RODC Password Replication Group', 'Denied RODC Password Replication Group', 'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers', 'Cloneable Domain Controllers', 'Protected Users', 'Key Admins', 'Enterprise Key Admins', 'DnsAdmins', 'DnsUpdateProxy'
    $objects = 'Users', 'Groups', 'Computers'

    $prefBackup = $WarningPreference
    $WarningPreference = 'SilentlyContinue'

    if ($cred -Ne [PSCredential]::Empty) {
        $common = New-Object -TypeName PowerViewWrapperCommon -ArgumentList $cred
    } else {
        $common = New-Object -TypeName PowerViewWrapperCommon
    }

    ForEach ($domain in $common.Domains) {
        Write-Host "[*] Domain ${domain} SID: $($common.DomainSIDs["$domain"])"
        $WarningPreference = 'SilentlyContinue'
        if ($cred -Ne [PSCredential]::Empty) {
            $container = New-Object -TypeName PowerViewWrapper -ArgumentList $domain, $cred
        } else {
            $container = New-Object -TypeName PowerViewWrapper -ArgumentList $domain
        }
        $WarningPreference = $prefBackup
        Write-Host "[*] Domain Controller information (${domain})"
        $container.DomainController | Select-Object IPAddress, Name, Domain, Forest | Format-Table
        Write-Host "[*] Users (${domain})"
        $container.DomainUser | Select-Object SamAccountName | Format-Table
        Write-Host "[*] Members belonging to Domain Admins (${domain})"
        $container.DomainAdmins | Select-Object MemberName | Format-Table
        Write-Host "[*] Members belonging to Enterprise Admins (${domain})"
        $container.EnterpriseAdmins | Select-Object MemberName | Format-Table
        Write-Host "[*] Groups (${domain})"
        $groupObjects = $container.DomainGroup | Where-Object { -Not ($_.GroupType -Match 'CREATED_BY_SYSTEM') } | Select-Object MemberOf, SamAccountName, Member, ObjectSID
        $groupObjects | Select-Object SamAccountName | Format-Table
        Write-Host "[*] Potentially interesting Groups (${domain})"
        $groups = @()
        $groupsMemberOfs = @()
        $groupsMembers = @()
        $groupsRID1000s = @()
        ForEach ($currentGroup in $groupObjects) {
            $group = $currentGroup | Select-Object -ExpandProperty SamAccountName
            if ($wellKnownDomainGroups -Contains $group -Or $wellKnownLocalGroups -Contains $group) {
                Continue
            }
            $temp = New-Object PSObject
            $temp | Add-Member NoteProperty 'SamAccountName' $group
            $groups += $temp
            $memberOfs = $currentGroup | Select-Object -ExpandProperty MemberOf -ErrorAction SilentlyContinue
            if ($memberOfs -Ne $null) {
                $groupsMemberOfs += ReturnGroupMemberOfs $group $memberOfs
            }
            $members = $currentGroup | Select-Object -ExpandProperty Member -ErrorAction SilentlyContinue
            if ($members -Ne $null) {
                $groupsMembers += ReturnGroupMembers $group $members
            }
            $rid = $currentGroup | Select-Object ObjectSID
            if ($rid -Match 'S-1-5-21-[0-9]+-[0-9]+-' -And [Int]($_.ObjectSID -split '-' | Select-Object -Last 1) -Ge 1000) {
                $temp | Add-Member NoteProperty 'ObjectSID'
                $groupsRID1000s += $temp
            }
        }
        if ($groups -Ne @()) {
            $groups | Format-Table
        }
        Write-Host "[*] Potentially interesting Groups parents (${domain})"
        if ($groupsMemberOfs -Ne @()) {
            $groupsMemberOfs | Format-Table
        }
        Write-Host "[*] Potentially interesting Groups members (${domain})"
        if ($groupsMembers -Ne @()) {
            $groupsMembers | Format-Table
        }
        Write-Host "[*] Groups having RID greater than or equal to 1000 (${domain})"
        if ($groupsRID1000s -Ne @()) {
            $groupsRID1000s | Format-Table
        }
        Write-Host "[*] Computers (${domain})"
        $container.DomainComputer | Select-Object DnsHostName | Foreach-Object { $_ | Add-Member -NotePropertyName ipaddress -NotePropertyValue (Resolve-DnsName -Name ($_.dnshostname) | Select-Object -ExpandProperty IPAddress | Where-Object { $_ -Ne '::1' }) -Force; $_ } | Format-Table IPAddress, dnshostname
        Write-Host "[*] LAPS Computers (${domain})"
        $container.DomainComputer | Where-Object { $_.'ms-mcs-admpwdexpirationtime' -ne $null } | Select-Object DnsHostName, ms-mcs-admpwd | Format-Table
        Write-Host "[*] Unconstrained Delegation Computers (${domain})"
        $container.Unconstrained | Select-Object SamAccountName | Format-Table
        $domainController = $container.DomainComputer | Select-Object -ExpandProperty Name
        ForEach($dc in $domainController) { 
            $result = Get-ChildItem -Path "\\${dc}\pipe\spoolss" -ErrorAction SilentlyContinue
            if ($result -Ne $null) {
                Write-Host "[+] `"${dc}`" is running Print Spooler!"
            } else {
                Write-Host "[-] `"${dc}`" seems not running Print Spooler ... Check yourself"
            }
        }
        Write-Host "[*] Constrained Delegation Users (${domain})"
        $container.ConstrainedUser | Select-Object SamAccountName, msds-allowedToDelegateTo | Format-Table
        Write-Host "[*] Constrained Delegation Computers (${domain})"
        $container.ConstrainedComputer | Select-Object SamAccountName, msds-allowedToDelegateTo | Format-Table
        Write-Host "[*] RBCD Computers (${domain})"
        $container.ResourceBasedConstrained | Select-Object SamAccountName, msds-allowedtoactionbehalfofotheridentity | Format-Table
        Write-Host "[*] SPN User John Hashes (${domain})"
        $container.JohnHashes | Format-Table

        ForEach ($attackers in $objects) {
            ForEach ($targets in $objects) {
                Write-Host "[*] List of ${attackers} that have abilities against ${targets} (${domain})"
                $currents = $container.EnumWritable($attackers, $targets)
                $identities = $currents | Select-Object Identity -Unique
                $identities | Format-Table

                if ($attackers -Eq 'Users') {
                    ForEach ($user in $identities.Identity) {
                        if ($wellKnownUsers -Contains $user) {
                            Continue
                        }
                        Write-Host "[+] The user `"${user}`" has ability against ${targets}! (${domain})"
                        PrintAbilities ($currents | Where-Object { $_.Identity -Eq $user })
                    }
                }
                if ($attackers -Eq 'Groups') {
                    ForEach ($group in $identities.Identity) {
                        if ($wellKnownLocalGroups -Contains $group -Or $wellKnownDomainGroups -Contains $group) {
                            Continue
                        }
                        Write-Host "[+] The group `"${group}`" has ability against ${targets}! (${domain})"
                        PrintAbilities ($currents | Where-Object { $_.Identity -Eq $group })

                        $memberOfs = $container.DomainGroup | Where-Object { $_.SamAccountName -Eq $group } | Select-Object -ExpandProperty MemberOf -ErrorAction SilentlyContinue
                        Write-Host "[+] The parents of the `"${group}`" group (${domain})"
                        if ($memberOfs -Ne $null) {
                            ReturnGroupMemberOfs $group $memberOfs | Format-Table
                        }
                        $members = $container.DomainGroup | Where-Object { $_.SamAccountName -Eq $group } | Select-Object -ExpandProperty Member -ErrorAction SilentlyContinue
                        Write-Host "[+] The members of the `"${group}`" group (${domain})"
                        if ($members -Ne $null) {
                            ReturnGroupMembers $group $members | Format-Table
                        }
                    }
                }
                if ($attackers -Eq 'Computers') {
                    ForEach ($computer in $identities.Identity) {
                        Write-Host "[+] The computer `"${computer}`" has ability against ${targets}! (${domain})"
                        PrintAbilities ($currents | Where-Object { $_.Identity -Eq $computer })
                    }
                }
            }
        }
        Write-Host "[*] Last logon users (${domain})"
        $container.LastLoggedOn | Format-Table
        Write-Host "[*] Cached RDP connections (${domain})"
        $container.CachedRDP | Format-Table
        Write-Host '-------------------------------'
    }

    Write-Host '[*] External Domain Users and Groups'
    $common.ExternalUsersAndGroups | Format-Table
    Write-Host '[*] Domain Trust Mapping. Check TREAT_AS_EXTERNAL'
    $common.DomainTrustMapping | Format-Table
    Write-Host '[*] Invoke-ShareFinder'
    $common.Shares | Format-Table
}