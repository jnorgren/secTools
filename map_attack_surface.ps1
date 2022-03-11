[CmdletBinding()]
param (
    [Parameter()]
    [string[]]$domains,

    [Parameter()]
    [bool]$map_ip_space
)

Import-Module -Name DnsClient


function domain_enum {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$domain
    )
    $crt_sh = "https://crt.sh/?dNSName=%25.$domain&output=json"
    $results = Invoke-RestMethod -Uri $crt_sh
    $domain_list = $($results.name_value)
    $domain_list = ($domain_list.Replace("*.", "")).trim() | Select-Object -Unique
    return $domain_list
}

function enum_ip_space {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$domain_list
    )
    $IPs = @()
    $counter = 0
    foreach ($name in $domain_list) {
        $counter++
        Write-Progress -Activity 'Enumerating Public IP Space from domain list...' -PercentComplete (($counter / $domain_list.count) * 100)
        $IPs += ((Resolve-DnsName -Name $name -ErrorAction SilentlyContinue -QuickTimeout -Type A).IP4Address)
    }
    $ipSpace = $IPs | Select-Object -Unique
    return $ipSpace
}

$domain_list = @()
foreach($domain in $domains) {
    $domain_list += domain_enum -domain $domain  
}
$domain_list

if($map_ip_space -eq $true) {
    enum_ip_space -domain_list $domain_list
}


