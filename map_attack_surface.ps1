[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]]$domains,

    [Parameter()]
    [switch]$map_ip_space = $false
)

Import-Module -Name DnsClient

function domain_enum {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$domain
    )
    Begin {
        $crt_sh_base = "https://crt.sh/?dNSName=%25."
        $output_format = "&output=json"
    }
    Process {
        try {
            $crt_sh = "$crt_sh_base$domain$output_format"
            $results = Invoke-RestMethod -Uri $crt_sh
            $domain_list = $results.common_name.Replace("*.", "").Trim() | Select-Object -Unique
            return $domain_list
        } catch {
            Write-Error "Error retrieving data for domain $($domain): $_"
        }
    }
    End {}
}

function enum_ip_space {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$domain_list
    )
    Begin {
        $counter = 0
        $items = @()
    }
    Process {
        foreach ($name in $domain_list) {
            $counter++
            Write-Progress -Activity 'Enumerating Public IP Space from domain list...' -PercentComplete (($counter / $domain_list.count) * 100)
            $dns_responses = Resolve-DnsName -Name $name -ErrorAction SilentlyContinue -QuickTimeout
            foreach ($response in $dns_responses) {
                if ($response.QueryType -eq 'CNAME') {
                    $item = New-Object PSObject -Property @{
                        Domain = $name
                        CNAME = $($response.NameHost)
                        IPAddress = ''
                    }
                    $items += $item
                } elseif ($response.QueryType -eq 'A') {
                    $item = New-Object PSObject -Property @{
                        Domain = $($response.Name)
                        CNAME = ''
                        IPAddress = $($response.IPAddress)
                    }
                    $items += $item
                } elseif ($response.QueryType -eq 'AAAA') {
                    $item = New-Object PSObject -Property @{
                        Domain = $($response.Name)
                        CNAME = ''
                        IPAddress = $($response.IP6Address)
                    }
                    $items += $item
                }
            }
        }
    }
    End {
        $items | Format-Table -Property Domain, CNAME, IPAddress -AutoSize
        return $items
    }
}

$domain_list = foreach ($domain in $domains) {
    domain_enum -domain $domain
}

$domain_list

if ($map_ip_space) {
    $results = enum_ip_space -domain_list $domain_list
    $results | Select-Object -Property Domain, CNAME, IPAddress
}
