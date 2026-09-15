#requires -Version 5.1
<#
.SYNOPSIS
    Maps the public attack surface of one or more domains using certificate
    transparency logs and DNS-over-HTTPS.

.DESCRIPTION
    Runs on Windows PowerShell 5.1 and PowerShell 7+ on Windows, macOS and Linux.
    No platform-specific modules are used: hostnames come from CT log search APIs
    and resolution is done over DNS-over-HTTPS JSON, so there is a single code
    path on every platform.

    CT sources (see -source):
      CertSpotter  api.certspotter.com - full SAN data, cursor pagination.
                   Set CERTSPOTTER_API_KEY for usable rate limits; without a key
                   subdomain queries are capped at roughly 10/day.
      CrtSh        crt.sh - no account required, but frequently slow or down.
      Auto         CertSpotter first, falling back to crt.sh on failure.

.PARAMETER domains
    One or more registered domains to enumerate, e.g. contoso.com.

.PARAMETER map_ip_space
    Resolve every discovered hostname to A/AAAA/CNAME records.

.PARAMETER include_certificates
    Emit one row per (hostname, certificate) pair showing which certificate each
    hostname was found in, instead of a plain list of hostnames. The two
    providers expose different identifiers, so the columns populated depend on
    the source:

      Column        CertSpotter                 CrtSh
      ------        -----------                 -----
      CertId        issuance id                 crt.sh certificate id
      CertSha256    cert_sha256 fingerprint     (empty - not in crt.sh JSON)
      SerialNumber  (empty - not exposed)       serial_number
      Issuer        issuer.name                 issuer_name
      CertUrl       crt.sh/?q=<sha256>          crt.sh/?id=<id>

    CertUrl is a browser link. crt.sh rejects output=json for hash lookups, so
    it is not usable as an API endpoint.

    Can be combined with -map_ip_space, in which case the certificate rows are
    emitted first, followed by the resolution rows.

.PARAMETER source
    Which CT log search provider to use. Defaults to Auto.

.PARAMETER doh_endpoint
    DNS-over-HTTPS JSON endpoint used for resolution. Defaults to Google, which
    returns JSON without needing an Accept header (Windows PowerShell 5.1 treats
    Accept as a restricted .NET header, so the default path avoids sending one).
    Cloudflare (https://cloudflare-dns.com/dns-query) and Quad9
    (https://dns.quad9.net:5053/dns-query) also work and are sent the required
    application/dns-json Accept header automatically.

.EXAMPLE
    ./map_attack_surface.ps1 -domains contoso.com

.EXAMPLE
    ./map_attack_surface.ps1 -domains contoso.com, fabrikam.com -map_ip_space

.EXAMPLE
    $env:CERTSPOTTER_API_KEY = 'xxxx'
    ./map_attack_surface.ps1 -domains contoso.com -source CertSpotter -map_ip_space
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]]$domains,

    [Parameter()]
    [switch]$map_ip_space,

    [Parameter()]
    [switch]$include_certificates,

    [Parameter()]
    [ValidateSet('Auto', 'CertSpotter', 'CrtSh')]
    [string]$source = 'Auto',

    [Parameter()]
    [string]$doh_endpoint = 'https://dns.google/resolve',

    [Parameter()]
    [ValidateRange(5, 600)]
    [int]$timeout_sec = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 still negotiates TLS 1.0 by default, which every one of
# these endpoints rejects. PowerShell 7 uses the OS default and needs no help.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

$script:user_agent = 'map_attack_surface.ps1/2.0 (+secTools)'

# DNS record type numbers as they appear in DoH JSON responses.
$script:dns_types = @{
    A     = 1
    CNAME = 5
    AAAA  = 28
}

function get_http_status {
    # Extracts an HTTP status code from a terminating error raised by
    # Invoke-RestMethod. 5.1 throws WebException, 7 throws
    # HttpResponseException; the Response.StatusCode enum casts the same on both.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$error_record
    )
    $response = $error_record.Exception.PSObject.Properties['Response']
    if (-not $response -or $null -eq $response.Value) { return 0 }
    try { return [int]$response.Value.StatusCode } catch { return 0 }
}

function invoke_json_api {
    # Invoke-RestMethod wrapper with retry/backoff. -MaximumRetryCount does not
    # exist in 5.1, so the retry loop is hand-rolled to keep one code path.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$uri,

        [Parameter()]
        [hashtable]$headers = @{},

        [Parameter()]
        [int]$max_attempts = 3
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-RestMethod -Uri $uri -Headers $headers -Method Get `
                -TimeoutSec $timeout_sec -UserAgent $script:user_agent
        } catch {
            $status = get_http_status -error_record $_
            $retryable = ($status -eq 429 -or $status -ge 500 -or $status -eq 0)
            if (-not $retryable -or $attempt -ge $max_attempts) { throw }

            $backoff = [math]::Pow(2, $attempt)
            Write-Verbose "HTTP $status from $uri, retrying in $backoff s (attempt $attempt/$max_attempts)"
            Start-Sleep -Seconds $backoff
        }
    }
}

function normalize_hostnames {
    # CT logs contain wildcards, trailing dots, mixed case, and the occasional
    # email address or malformed identity. Reduce all of it to resolvable names.
    [CmdletBinding()]
    param (
        [Parameter()]
        [AllowNull()]
        [string[]]$names
    )
    if (-not $names) { return @() }

    $cleaned = foreach ($name in $names) {
        foreach ($part in ($name -split "`n")) {
            $host_name = $part.Trim().TrimEnd('.').ToLowerInvariant()
            $host_name = $host_name -replace '^\*\.', ''
            if ($host_name -match '^[a-z0-9._-]+\.[a-z]{2,}$' -and $host_name -notmatch '@') {
                $host_name
            }
        }
    }
    return @($cleaned | Sort-Object -Unique)
}

function as_datetime {
    # crt.sh dates deserialize to [datetime]; Cert Spotter returns RFC 3339
    # strings. Normalize so NotBefore/NotAfter sort correctly regardless of source.
    [CmdletBinding()]
    param (
        [Parameter()]
        [AllowNull()]
        $value
    )
    if (-not $value) { return $null }
    if ($value -is [datetime]) { return $value }
    try {
        return [datetime]::Parse([string]$value, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind)
    } catch { return $null }
}

function new_cert_row {
    # One row per (hostname, certificate) pair. The two providers expose
    # disjoint identifiers - Cert Spotter has the SHA-256 fingerprint but no
    # serial, crt.sh has the serial and issuer but no fingerprint - so both
    # columns exist and whichever the source supplies is populated.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$hostname,
        [Parameter(Mandatory)][string]$source_name,
        [Parameter()][AllowNull()]$cert_id,
        [Parameter()][string]$sha256 = '',
        [Parameter()][string]$serial = '',
        [Parameter()][string]$issuer = '',
        [Parameter()][AllowNull()]$not_before,
        [Parameter()][AllowNull()]$not_after,
        [Parameter()][string]$cert_url = ''
    )
    return [pscustomobject][ordered]@{
        Hostname     = $hostname
        Source       = $source_name
        CertId       = $cert_id
        CertSha256   = $sha256
        SerialNumber = $serial
        Issuer       = $issuer
        NotBefore    = as_datetime -value $not_before
        NotAfter     = as_datetime -value $not_after
        CertUrl      = $cert_url
    }
}

function ct_certspotter {
    # https://sslmate.com/help/reference/ct_search_api_v1
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$domain
    )
    # No Accept header: the API always returns JSON, and 5.1 restricts that
    # header. Authorization is not restricted, so it is safe on both editions.
    $headers = @{}
    if ($env:CERTSPOTTER_API_KEY) {
        $headers['Authorization'] = "Bearer $($env:CERTSPOTTER_API_KEY)"
    } else {
        Write-Warning 'CERTSPOTTER_API_KEY is not set; unauthenticated subdomain queries are heavily rate limited.'
    }

    $base = 'https://api.certspotter.com/v1/issuances' +
            "?domain=$([uri]::EscapeDataString($domain))" +
            '&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer'

    $rows = [System.Collections.Generic.List[psobject]]::new()
    $after = $null
    $page = 0

    # Cursor pagination: pass the last issuance id back as `after` until the
    # endpoint returns an empty array.
    while ($true) {
        $page++
        $uri = if ($after) { "$base&after=$([uri]::EscapeDataString($after))" } else { $base }
        $results = invoke_json_api -uri $uri -headers $headers

        # Errors come back as HTTP 200 with a {code, message} body rather than a
        # 4xx status, so they have to be detected on the payload. Without this a
        # rate-limited run looks identical to a domain with no certificates.
        if ($results -and $results.PSObject.Properties['code']) {
            throw "Cert Spotter API error '$($results.code)': $($results.message)"
        }

        if (-not $results -or @($results).Count -eq 0) { break }

        foreach ($issuance in @($results)) {
            $sha256 = if ($issuance.PSObject.Properties['cert_sha256']) { [string]$issuance.cert_sha256 } else { '' }

            $issuer_name = ''
            if ($issuance.PSObject.Properties['issuer'] -and $issuance.issuer -and
                $issuance.issuer.PSObject.Properties['name']) {
                $issuer_name = [string]$issuance.issuer.name
            }

            # crt.sh renders a cert page for a SHA-256 fingerprint. HTML only -
            # output=json is rejected for hash lookups - but it is a working link.
            $cert_url = if ($sha256) { "https://crt.sh/?q=$sha256" } else { '' }

            if (-not $issuance.PSObject.Properties['dns_names']) { continue }

            foreach ($hostname in (normalize_hostnames -names $issuance.dns_names)) {
                $rows.Add((new_cert_row -hostname $hostname -source_name 'CertSpotter' `
                    -cert_id $issuance.id -sha256 $sha256 -issuer $issuer_name `
                    -not_before $issuance.not_before -not_after $issuance.not_after `
                    -cert_url $cert_url))
            }
        }

        $after = @($results)[-1].id
        Write-Verbose "Cert Spotter page $page for $domain : $(@($results).Count) issuances, $($rows.Count) rows so far"

        if ($page -ge 100) {
            Write-Warning "Stopped paginating $domain at $page pages."
            break
        }
    }

    return $rows
}

function ct_crtsh {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$domain
    )
    # `q` matches both common names and SANs. name_value carries the full SAN
    # list as newline-separated text, which is where most hostnames actually live.
    $uri = "https://crt.sh/?q=%25.$([uri]::EscapeDataString($domain))&output=json"
    $results = invoke_json_api -uri $uri

    $rows = [System.Collections.Generic.List[psobject]]::new()
    foreach ($entry in @($results)) {
        $names = [System.Collections.Generic.List[string]]::new()
        if ($entry.PSObject.Properties['name_value'] -and $entry.name_value) {
            $names.Add($entry.name_value)
        }
        if ($entry.PSObject.Properties['common_name'] -and $entry.common_name) {
            $names.Add($entry.common_name)
        }

        $serial = if ($entry.PSObject.Properties['serial_number']) { [string]$entry.serial_number } else { '' }
        $issuer_name = if ($entry.PSObject.Properties['issuer_name']) { [string]$entry.issuer_name } else { '' }

        # crt.sh has no SHA-256 in its JSON output; its own id is the stable
        # identifier and links straight to the certificate page.
        $cert_url = if ($entry.PSObject.Properties['id']) { "https://crt.sh/?id=$($entry.id)" } else { '' }

        foreach ($hostname in (normalize_hostnames -names $names)) {
            $rows.Add((new_cert_row -hostname $hostname -source_name 'CrtSh' `
                -cert_id $entry.id -serial $serial -issuer $issuer_name `
                -not_before $entry.not_before -not_after $entry.not_after `
                -cert_url $cert_url))
        }
    }

    return $rows
}

function domain_enum {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$domain,

        [Parameter()]
        [string]$provider = 'Auto'
    )

    $providers = switch ($provider) {
        'CertSpotter' { @('CertSpotter') }
        'CrtSh'       { @('CrtSh') }
        default       { @('CertSpotter', 'CrtSh') }
    }

    foreach ($name in $providers) {
        try {
            Write-Verbose "Querying $name for $domain"
            # @() guards against PowerShell unrolling a single-element result
            # to a bare string, which would break .Count below.
            $found = @(switch ($name) {
                'CertSpotter' { ct_certspotter -domain $domain }
                'CrtSh'       { ct_crtsh -domain $domain }
            })
            if ($found.Count -gt 0) {
                $unique_hosts = @($found | Select-Object -ExpandProperty Hostname | Sort-Object -Unique).Count
                Write-Verbose "$name returned $unique_hosts hostnames across $($found.Count) certificate rows for $domain"
                return $found
            }
            Write-Warning "$name returned no hostnames for $domain."
        } catch {
            Write-Warning "$name failed for $($domain): $($_.Exception.Message)"
        }
    }

    Write-Error "No CT source returned results for $domain."
    return @()
}

function resolve_doh {
    # DNS-over-HTTPS JSON (RFC 8484 endpoints with the application/dns-json
    # content type). Works identically on every platform and PowerShell edition,
    # unlike Resolve-DnsName which is Windows-only.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$name,

        [Parameter(Mandatory)]
        [ValidateSet('A', 'AAAA')]
        [string]$type
    )
    $uri = "$doh_endpoint" +
           "?name=$([uri]::EscapeDataString($name))" +
           "&type=$type"

    # dns.google/resolve always returns JSON. Every other DoH endpoint requires
    # an application/dns-json Accept header, which is only sent when needed
    # because Windows PowerShell 5.1 restricts that header on HttpWebRequest.
    $headers = @{}
    if ($doh_endpoint -notmatch '^https://dns\.google/resolve') {
        $headers['Accept'] = 'application/dns-json'
    }

    try {
        $response = invoke_json_api -uri $uri -headers $headers -max_attempts 2
    } catch {
        Write-Verbose "DoH $type query failed for $($name): $($_.Exception.Message)"
        return @()
    }

    if (-not $response -or -not $response.PSObject.Properties['Answer'] -or -not $response.Answer) {
        return @()
    }
    return @($response.Answer)
}

function enum_ip_space {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$domain_list
    )
    Begin {
        # List<T> instead of `$items +=`, which reallocates the whole array on
        # every append and turns large hostname sets into O(n^2).
        $items = [System.Collections.Generic.List[psobject]]::new()
        $counter = 0
        $total = $domain_list.Count
    }
    Process {
        foreach ($name in $domain_list) {
            $counter++
            if ($total -gt 0) {
                Write-Progress -Activity 'Enumerating public IP space from domain list...' `
                    -Status "$counter/$total  $name" `
                    -PercentComplete (($counter / $total) * 100)
            }

            # The A query returns the whole CNAME chain plus the terminal
            # addresses, so CNAMEs are read from it rather than queried separately.
            $answers = @(resolve_doh -name $name -type 'A') + @(resolve_doh -name $name -type 'AAAA')

            foreach ($answer in $answers) {
                $record_name = $answer.name.TrimEnd('.')

                switch ($answer.type) {
                    $script:dns_types.CNAME {
                        $items.Add([pscustomobject][ordered]@{
                            Domain    = $record_name
                            CNAME     = $answer.data.TrimEnd('.')
                            IPAddress = ''
                        })
                    }
                    { $_ -in $script:dns_types.A, $script:dns_types.AAAA } {
                        $items.Add([pscustomobject][ordered]@{
                            Domain    = $record_name
                            CNAME     = ''
                            IPAddress = $answer.data.Trim()
                        })
                    }
                }
            }
        }
    }
    End {
        Write-Progress -Activity 'Enumerating public IP space from domain list...' -Completed
        # The CNAME chain comes back on both the A and the AAAA query, so the
        # same link would otherwise be emitted twice per hostname.
        # No Format-Table here: formatting inside a function poisons the objects
        # for any downstream Export-Csv / Where-Object.
        return @($items | Sort-Object -Property Domain, CNAME, IPAddress -Unique)
    }
}

# Certificate rows: one per (hostname, certificate) pair.
$certificates = @(foreach ($domain in $domains) {
    domain_enum -domain $domain -provider $source
})

# The same hostname legitimately appears in many certificates, so the hostname
# list is the distinct projection of those rows.
$domain_list = @($certificates | Select-Object -ExpandProperty Hostname | Sort-Object -Unique)

Write-Verbose "Discovered $($domain_list.Count) unique hostnames across $($certificates.Count) certificate rows from $($domains.Count) domain(s)"

if ($include_certificates) {
    @($certificates | Sort-Object -Property Hostname, CertId -Unique | Sort-Object -Property Hostname, NotBefore)
}

if ($map_ip_space) {
    if ($domain_list.Count -eq 0) {
        Write-Warning 'No hostnames to resolve.'
        return
    }
    # Emitted as objects, not Format-Table. PowerShell renders a table for these
    # three properties automatically, and the caller can still pipe them into
    # Export-Csv, Where-Object or ConvertTo-Json.
    enum_ip_space -domain_list $domain_list
}

if (-not $include_certificates -and -not $map_ip_space) {
    $domain_list
}
