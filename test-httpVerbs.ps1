[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string[]]$domains
)

foreach ($domain in $domains) {
    try {
        $response = (Invoke-WebRequest -Uri "https://$domain" -Method Options -ErrorAction SilentlyContinue)
        if ($response) {
            Write-Output "$domain : $($response.statusCode)"
        }
    
    }
    catch {
        $_
    }

    if (!$response) {
        Write-Host "$domain does NOT support http Options method" -ForegroundColor Red
    }
    elseif ($($response.statuscode) -eq "200") {
        Write-Host "$domain supports the HTTP Options method" -ForegroundColor Green
    }
    else {
        Write-Host "Inconclusive http Option support on: $domain" -ForegroundColor Yellow
    }
}

