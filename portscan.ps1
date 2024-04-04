function PortScan {
    param(
        [Parameter(Position = 0, Mandatory = $True)] $ipAddress
    )

    $ports = 80, 443, 8080, 445, 1443, 3389, 5985
    ForEach($ip in $ipAddress) {
        ForEach($port in $ports) {
            $client = New-Object Net.Sockets.TcpClient
            if ($client.ConnectAsync($ip, $port).Wait(100)) {
                Write-Host "[+] ${ip} TCP Port ${port} Open"
            }
            $client.Close()
        }
    }
}