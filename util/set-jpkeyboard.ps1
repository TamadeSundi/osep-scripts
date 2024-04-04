$p='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters'
New-ItemProperty -Path $p -Name LayerDriverJPN -PropertyType String -Value kbd106.dll -Force
New-ItemProperty -Path $p -Name OverrideKeyboardSubtype -PropertyType DWord -Value 2
New-ItemProperty -Path $p -Name OverrideKeyboardType -PropertyType DWord -Value 7