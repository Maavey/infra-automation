#Set-ExecutionPolicy Bypass -Scope Process -Force
cls
$ScriptName = "Maverick Certificate Toolkit"
$ScriptVersion = "1.0.5"
$ScriptAuthor = "Maverick"
$ExpiryWarningDays = 30

function OK($m){ Write-Host "[OK] $m" -ForegroundColor Green }
function WARN($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function ERR($m){ Write-Host "[ERROR] $m" -ForegroundColor Red }
function SEC($m){ Write-Host "`n==== $m ====" -ForegroundColor Cyan }

function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " $ScriptName" -ForegroundColor White
    Write-Host " Version : $ScriptVersion" -ForegroundColor DarkGray
    Write-Host " By      : $ScriptAuthor" -ForegroundColor DarkGray
    Write-Host " Purpose : Safe certificate replacement for Exchange / IIS / ADFS / WAP / RDS" -ForegroundColor DarkGray
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-AdminNotice {
    if (Test-IsAdministrator) {
        OK "Running as Administrator. Full import/apply functionality is available."
    } else {
        WARN "Not running as Administrator. Detection is allowed, but import/apply operations will be blocked."
    }
}

function Require-AdministratorForApply {
    if (-not (Test-IsAdministrator)) {
        ERR "Import/apply requires an elevated PowerShell session. No changes were made."
        exit
    }
}

function Get-SanList($Cert) {
    $list = @()
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq "2.5.29.17") {
            foreach ($i in ($ext.Format($false) -split ", ")) {
                if ($i -match "DNS Name=(.+)") { $list += $matches[1].Trim().ToLower() }
                elseif ($i -match "DNS:(.+)") { $list += $matches[1].Trim().ToLower() }
            }
        }
    }
    return $list | Sort-Object -Unique
}

function Get-CertCN($Cert) {
    if (-not $Cert -or [string]::IsNullOrWhiteSpace($Cert.Subject)) { return $null }
    return (($Cert.Subject -replace "^CN=", "") -split ",")[0].Trim().ToLower()
}

function Test-Covered($Name, $Cert, $Sans) {
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }

    $name = $Name.Trim().ToLower()
    $cn = Get-CertCN $Cert

    if ($Sans -contains $name -or $cn -eq $name) { return $true }

    foreach ($san in $Sans) {
        if ($san.StartsWith("*.")) {
            $suffix = $san.Substring(1)
            if ($name.EndsWith($suffix) -and (($name.Split(".").Count) -eq ($san.Split(".").Count))) {
                return $true
            }
        }
    }

    if ($cn -and $cn.StartsWith("*.")) {
        $suffix = $cn.Substring(1)
        if ($name.EndsWith($suffix) -and (($name.Split(".").Count) -eq ($cn.Split(".").Count))) {
            return $true
        }
    }

    return $false
}

function Get-LocalMachineCertByThumbprint($Thumbprint) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    $clean = ($Thumbprint -replace " ", "").ToUpper()
    return Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $clean } |
        Select-Object -First 1
}

function Show-CertSummary($Label, $Cert) {
    Write-Host ""
    Write-Host $Label -ForegroundColor White
    if (-not $Cert) {
        WARN "Certificate not found/resolved."
        return
    }
    $days = [math]::Floor(($Cert.NotAfter - (Get-Date)).TotalDays)
    Write-Host "Subject    : $($Cert.Subject)"
    Write-Host "Thumbprint : $($Cert.Thumbprint)"
    Write-Host "Expires    : $($Cert.NotAfter)"
    Write-Host "Days Left  : $days"
}


function Get-CertExpiryColor($Cert) {
    if (-not $Cert -or -not $Cert.NotAfter) { return "DarkGray" }

    $days = [math]::Floor(($Cert.NotAfter - (Get-Date)).TotalDays)

    if ($days -lt 7) { return "Red" }
    elseif ($days -lt 30) { return "Yellow" }
    else { return "Green" }
}

function Show-CertExpiryLine($Label, $Cert) {
    if (-not $Cert) {
        Write-Host ("{0,-35} Certificate not found/resolved" -f $Label) -ForegroundColor DarkGray
        return
    }

    $days = [math]::Floor(($Cert.NotAfter - (Get-Date)).TotalDays)
    $color = Get-CertExpiryColor $Cert

    Write-Host ("{0,-35} Expires: {1} | Days Left: {2} | Thumbprint: {3}" -f `
        $Label, $Cert.NotAfter, $days, $Cert.Thumbprint) -ForegroundColor $color
}

function Show-CertExpiryLegend {
    Write-Host "Green = 30+ days | Yellow = less than 30 days | Red = less than 7 days" -ForegroundColor DarkGray
}

function Import-PfxToLocalMachineMy($PfxFile, $Password, $PreviewCert) {
    $existing = Get-LocalMachineCertByThumbprint $PreviewCert.Thumbprint
    if ($existing) {
        WARN "Certificate already exists in LocalMachine\My. Reusing existing certificate."
        return $existing
    }

    return Import-PfxCertificate `
        -FilePath $PfxFile.FullName `
        -CertStoreLocation Cert:\LocalMachine\My `
        -Password $Password `
        -Exportable
}

function Get-IisHttpsBindings {
    return Get-WebBinding -Protocol "https" | ForEach-Object {
        $binding = $_
        $sslHash = $binding.Attributes["certificateHash"].Value
        $store = $binding.Attributes["certificateStoreName"].Value
        if ([string]::IsNullOrWhiteSpace($store)) { $store = "My" }
        $bindingInfo = $binding.bindingInformation
        $parts = $bindingInfo -split ":", 3

        $thumb = $null
        $cert = $null

        if ($sslHash) {
            $thumb = ($sslHash -replace " ", "").ToUpper()
            $cert = Get-ChildItem Cert:\LocalMachine\$store -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $thumb } |
                Select-Object -First 1
        }

        [PSCustomObject]@{
            SiteName    = $_.ItemXPath -replace ".*name='([^']+)'.*", '$1'
            Binding     = $binding
            BindingInfo = $bindingInfo
            IP          = $parts[0]
            Port        = $parts[1]
            HostName    = $parts[2]
            Store       = $store
            Thumbprint  = $thumb
            Expires     = if ($cert) { $cert.NotAfter } else { $null }
            Cert        = $cert
        }
    }
}

function Get-NewPfxPreview {
    SEC "Detect New PFX Beside Script"

    $folder = Split-Path -Parent $MyInvocation.ScriptName
    if ([string]::IsNullOrWhiteSpace($folder)) { $folder = (Get-Location).Path }

    $pfxFile = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension.ToLower() -in @(".pfx", ".p12") } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $pfxFile) {
        ERR "No .pfx/.p12 file found beside script."
        exit
    }

    Write-Host "Using file: $($pfxFile.Name)"
    Write-Host "Full path : $($pfxFile.FullName)"
    Write-Host "Enter the PFX password. Type CANCEL to return/stop."

    $preview = $null
    $pfxPassword = $null

    while (-not $preview) {
        $plainPassword = Read-Host "Enter PFX password, or type CANCEL" -AsSecureString

        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($plainPassword)
        try {
            $plainCheck = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }

        if ($plainCheck -eq "CANCEL") {
            WARN "PFX password entry cancelled. No changes made."
            exit
        }

        try {
            $preview = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $pfxFile.FullName,
                $plainPassword,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            )
            $pfxPassword = $plainPassword
        } catch {
            ERR "Could not read PFX. Wrong password or invalid file. Please try again."
            $preview = $null
            $pfxPassword = $null
        }
    }

    $newSans = Get-SanList $preview
    Show-CertSummary "New PFX certificate:" $preview
    Write-Host "Private Key : $($preview.HasPrivateKey)"

    if ($newSans) {
        Write-Host "SANs:"
        $newSans | ForEach-Object { Write-Host " - $_" }
    }

    if (-not $preview.HasPrivateKey) {
        ERR "PFX has no private key. Cannot assign it to these roles."
        exit
    }

    return [PSCustomObject]@{
        File     = $pfxFile
        Password = $pfxPassword
        Cert     = $preview
        Sans     = $newSans
    }
}

function Test-CommandAvailable($Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-ServiceInstalled($Name) {
    return [bool](Get-Service -Name $Name -ErrorAction SilentlyContinue)
}

function Get-RoleAvailability {
    $roles = [ordered]@{}

    $iisModule = [bool](Get-Module -ListAvailable WebAdministration)
    $iisService = Test-ServiceInstalled "W3SVC"
    $roles["IIS"] = [PSCustomObject]@{
        Name      = "IIS"
        Available = ($iisModule -and $iisService)
        Reason    = if (-not $iisModule) { "Role not installed - IIS WebAdministration module/W3SVC not found" }
                    elseif (-not $iisService) { "Role not installed - IIS W3SVC service not found" }
                    else { "Available" }
    }

    $adfsCmds = @("Get-AdfsSslCertificate", "Set-AdfsSslCertificate", "Get-AdfsCertificate", "Set-AdfsCertificate")
    $missingAdfsCmds = @($adfsCmds | Where-Object { -not (Test-CommandAvailable $_) })
    $adfsService = Test-ServiceInstalled "adfssrv"
    $roles["ADFS"] = [PSCustomObject]@{
        Name      = "ADFS"
        Available = ($missingAdfsCmds.Count -eq 0 -and $adfsService)
        Reason    = if ($missingAdfsCmds.Count -gt 0) { "Role not installed - ADFS cmdlets/service not found" }
                    elseif (-not $adfsService) { "Role not installed - ADFS service not found" }
                    else { "Available" }
    }

    $wapCmds = @("Get-WebApplicationProxySslCertificate", "Set-WebApplicationProxySslCertificate", "Install-WebApplicationProxy")
    $missingWapCmds = @($wapCmds | Where-Object { -not (Test-CommandAvailable $_) })
    $wapService = Test-ServiceInstalled "appproxysvc"
    $roles["WAP"] = [PSCustomObject]@{
        Name      = "WAP / Web Application Proxy"
        Available = ($missingWapCmds.Count -eq 0 -and $wapService)
        Reason    = if ($missingWapCmds.Count -gt 0) { "Role not installed - WAP cmdlets/service not found" }
                    elseif (-not $wapService) { "Role not installed - WAP service not found" }
                    else { "Available" }
    }

    $exchangeCmds = @("Get-ExchangeCertificate", "Import-ExchangeCertificate", "Enable-ExchangeCertificate")
    $missingExchangeCmds = @($exchangeCmds | Where-Object { -not (Test-CommandAvailable $_) })
    $roles["EXCHANGE"] = [PSCustomObject]@{
        Name      = "Exchange"
        Available = ($missingExchangeCmds.Count -eq 0)
        Reason    = if ($missingExchangeCmds.Count -gt 0) { "Exchange cmdlets not found - run this script from Exchange Management Shell" }
                    else { "Available" }
    }

    Import-Module RemoteDesktop -ErrorAction SilentlyContinue
    $rdsCmds = @("Get-RDCertificate", "Set-RDCertificate")
    $missingRdsCmds = @($rdsCmds | Where-Object { -not (Test-CommandAvailable $_) })
    $rdsServices = @("TermService", "SessionEnv", "UmRdpService", "Tssdis")
    $installedRdsServices = @($rdsServices | Where-Object { Test-ServiceInstalled $_ })

    $roles["RDS"] = [PSCustomObject]@{
        Name      = "Remote Desktop Services"
        Available = ($missingRdsCmds.Count -eq 0 -or $installedRdsServices.Count -gt 0)
        Reason    = if ($missingRdsCmds.Count -gt 0 -and $installedRdsServices.Count -eq 0) {
                        "RDS/RDP not detected - RemoteDesktop cmdlets and RDS services not found"
                    }
                    elseif ($missingRdsCmds.Count -gt 0) {
                        "RDP services detected, but RemoteDesktop deployment cmdlets not found"
                    }
                    else {
                        "Available"
                    }
    }

    return $roles
}

function Get-RoleHealthColor($DaysLeft) {
    if ($DaysLeft -lt 7) { return "Red" }
    elseif ($DaysLeft -lt 30) { return "Yellow" }
    else { return "Green" }
}

function Get-MinDaysLeft($Dates) {
    $validDates = @($Dates | Where-Object { $_ })
    if ($validDates.Count -eq 0) { return $null }

    $days = @(
        $validDates | ForEach-Object {
            try { [math]::Floor((([datetime]$_) - (Get-Date)).TotalDays) } catch { $null }
        } | Where-Object { $null -ne $_ }
    )

    if ($days.Count -gt 0) { return ($days | Measure-Object -Minimum).Minimum }
    return $null
}

function Get-IisMenuMinDays {
    try {
        if (-not (Get-Module -ListAvailable WebAdministration)) { return $null }
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        $bindings = @(Get-IisHttpsBindings)
        $dates = @()

        foreach ($b in $bindings) {
            if ($b.Expires) { $dates += $b.Expires }
            elseif ($b.Cert -and $b.Cert.NotAfter) { $dates += $b.Cert.NotAfter }
        }

        return Get-MinDaysLeft $dates
    } catch { return $null }
}

function Get-AdfsMenuMinDays {
    try {
        $dates = @()

        if (Get-Command Get-AdfsSslCertificate -ErrorAction SilentlyContinue) {
            $ssl = Get-AdfsSslCertificate -ErrorAction SilentlyContinue
            if ($ssl.CertificateHash) {
                $cert = Get-LocalMachineCertByThumbprint $ssl.CertificateHash
                if ($cert -and $cert.NotAfter) { $dates += $cert.NotAfter }
            }
        }

        if (Get-Command Get-AdfsCertificate -ErrorAction SilentlyContinue) {
            $svc = Get-AdfsCertificate -CertificateType Service-Communications -ErrorAction SilentlyContinue
            if ($svc.Thumbprint) {
                $cert = Get-LocalMachineCertByThumbprint $svc.Thumbprint
                if ($cert -and $cert.NotAfter) { $dates += $cert.NotAfter }
            }
            elseif ($svc.NotAfter) {
                $dates += $svc.NotAfter
            }
        }

        return Get-MinDaysLeft $dates
    } catch { return $null }
}

function Get-WapMenuMinDays {
    try {
        $dates = @()

        if (Get-Command Get-WebApplicationProxySslCertificate -ErrorAction SilentlyContinue) {
            $wap = Get-WebApplicationProxySslCertificate -ErrorAction SilentlyContinue

            if ($wap.Thumbprint) {
                $cert = Get-LocalMachineCertByThumbprint $wap.Thumbprint
                if ($cert -and $cert.NotAfter) { $dates += $cert.NotAfter }
            }
            elseif ($wap.CertificateHash) {
                $cert = Get-LocalMachineCertByThumbprint $wap.CertificateHash
                if ($cert -and $cert.NotAfter) { $dates += $cert.NotAfter }
            }
        }

        return Get-MinDaysLeft $dates
    } catch { return $null }
}

function Get-ExchangeMenuMinDays {
    try {
        if (-not (Get-Command Get-ExchangeCertificate -ErrorAction SilentlyContinue)) { return $null }

        $certs = @(
            Get-ExchangeCertificate -ErrorAction SilentlyContinue |
            Where-Object { $_.Services.ToString() -ne "None" }
        )

        return Get-MinDaysLeft ($certs | ForEach-Object { $_.NotAfter })
    } catch { return $null }
}

function Get-RdsMenuMinDays {
    try {
        Import-Module RemoteDesktop -ErrorAction SilentlyContinue
        if (-not (Get-Command Get-RDCertificate -ErrorAction SilentlyContinue)) { return $null }

        $rdsCerts = @()

        try {
            $rdsCerts = @(Get-RDCertificate -ConnectionBroker $env:COMPUTERNAME -ErrorAction Stop)
        } catch {
            try {
                $rdsCerts = @(Get-RDCertificate -ErrorAction Stop)
            } catch {
                $rdsCerts = @()
            }
        }

        $dates = @()
        foreach ($rc in $rdsCerts) {
            if ($rc.ExpiresOn) {
                $dates += $rc.ExpiresOn
            }
            elseif ($rc.Thumbprint) {
                $cert = Get-LocalMachineCertByThumbprint $rc.Thumbprint
                if ($cert -and $cert.NotAfter) { $dates += $cert.NotAfter }
            }
        }

        return Get-MinDaysLeft $dates
    } catch { return $null }
}

function Write-RoleMenuLine($Number, $Key, $Info) {

    $text = "$Number. $($Info.Name)"

    if (-not $Info.Available) {
        Write-Host "$text [Unavailable - $($Info.Reason)]" -ForegroundColor DarkGray
        return
    }

    $minDays = $null

    switch ($Key) {
        "IIS"      { $minDays = Get-IisMenuMinDays }
        "ADFS"     { $minDays = Get-AdfsMenuMinDays }
        "WAP"      { $minDays = Get-WapMenuMinDays }
        "EXCHANGE" { $minDays = Get-ExchangeMenuMinDays }
        "RDS"      { $minDays = Get-RdsMenuMinDays }
    }

    if ($null -ne $minDays) {
        $color = Get-RoleHealthColor $minDays
        Write-Host "$text [$minDays days left]" -ForegroundColor $color
    } else {
        Write-Host "$text [Available]" -ForegroundColor White
    }
}

function Select-Role {
    SEC "Select Role"

    $roles = Get-RoleAvailability

    Write-RoleMenuLine 1 "IIS" $roles["IIS"]
    Write-RoleMenuLine 2 "ADFS" $roles["ADFS"]
    Write-RoleMenuLine 3 "WAP" $roles["WAP"]
    Write-RoleMenuLine 4 "EXCHANGE" $roles["EXCHANGE"]
    Write-RoleMenuLine 5 "RDS" $roles["RDS"]
    Write-Host ""

    Write-Host "Unavailable roles are shown for visibility but cannot be selected." -ForegroundColor DarkGray
    $roleInput = Read-Host "Choose available role: 1/IIS, 2/ADFS, 3/WAP, 4/Exchange, or 5/RDS"

    $selectedKey = $null

    switch ($roleInput.Trim().ToUpper()) {
        "1"        { $selectedKey = "IIS" }
        "IIS"      { $selectedKey = "IIS" }
        "2"        { $selectedKey = "ADFS" }
        "ADFS"     { $selectedKey = "ADFS" }
        "3"        { $selectedKey = "WAP" }
        "WAP"      { $selectedKey = "WAP" }
        "4"        { $selectedKey = "EXCHANGE" }
        "EXCHANGE" { $selectedKey = "EXCHANGE" }
        "5"        { $selectedKey = "RDS" }
        "RDS"      { $selectedKey = "RDS" }
        default {
            ERR "Invalid role."
            exit
        }
    }

    if (-not $roles[$selectedKey].Available) {
        ERR "$($roles[$selectedKey].Name) is unavailable: $($roles[$selectedKey].Reason)"
        exit
    }

    return $selectedKey
}

function Invoke-IisReplace {
    SEC "IIS Pre-Check"

    if (-not (Get-Module -ListAvailable WebAdministration)) {
        ERR "IIS WebAdministration module not found."
        exit
    }
    Import-Module WebAdministration -ErrorAction Stop

    SEC "Current IIS Certificates"
    $httpsBindings = @(Get-IisHttpsBindings)
    if (-not $httpsBindings -or $httpsBindings.Count -eq 0) {
        ERR "No IIS HTTPS bindings found."
        exit
    }

    $httpsBindings | Select-Object SiteName, BindingInfo, Port, HostName, Thumbprint, Expires | Format-Table -AutoSize

    SEC "IIS Certificate Expiry Status"
    Show-CertExpiryLegend
    foreach ($b in $httpsBindings) {
        Show-CertExpiryLine "IIS $($b.SiteName) :$($b.Port)" $b.Cert
    }

    $targetIisBindings = @($httpsBindings | Where-Object { $_.Port -eq "443" })
    $skippedIisBindings = @($httpsBindings | Where-Object { $_.Port -ne "443" })

    if ($skippedIisBindings.Count -gt 0) {
        WARN "Skipping non-443 HTTPS bindings. These will NOT be changed:"
        $skippedIisBindings | Select-Object SiteName, BindingInfo, Port, HostName, Thumbprint, Expires | Format-Table -AutoSize
    }

    if ($targetIisBindings.Count -eq 0) {
        ERR "No IIS HTTPS bindings on port 443 found."
        exit
    }

    $pfx = Get-NewPfxPreview

    SEC "IIS 443 Coverage Check"
    $requiredNames = $targetIisBindings.HostName |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique

    $missing = @()
    foreach ($name in $requiredNames) {
        if (Test-Covered $name $pfx.Cert $pfx.Sans) { OK $name }
        else { ERR "$name missing"; $missing += $name }
    }

    if ($missing.Count -gt 0) {
        ERR "New certificate does not cover all IIS 443 binding hostnames. Stop."
        exit
    }

    SEC "Final Confirmation"
    Write-Host "This will IMPORT the PFX and ASSIGN it to IIS HTTPS bindings on port 443 ONLY."
    Write-Host "Non-443 bindings, including Exchange Backend 444, will NOT be changed."
    Write-Host "iisreset will be executed after assignment."
    Write-Host "Old certificates will NOT be removed."
    $confirm = Read-Host "Type APPLY to import and assign"
    if ($confirm -ne "APPLY") { WARN "Cancelled. No changes made."; exit }

    Require-AdministratorForApply

    try {
        $imported = Import-PfxToLocalMachineMy $pfx.File $pfx.Password $pfx.Cert
        OK "Certificate ready in LocalMachine\My: $($imported.Thumbprint)"

        foreach ($b in $targetIisBindings) {
            $b.Binding.RemoveSslCertificate()
            $b.Binding.AddSslCertificate($imported.Thumbprint, "My")
            OK "Updated IIS 443 binding: $($b.SiteName) / $($b.BindingInfo)"
        }

        SEC "IIS Reset"
        iisreset
    } catch {
        ERR "IIS update failed: $($_.Exception.Message)"
        exit
    }

    SEC "Final IIS Verification"
    $finalIisBindings = @(Get-IisHttpsBindings)
    $finalIisBindings | Select-Object SiteName, BindingInfo, Port, HostName, Thumbprint, Expires | Format-Table -AutoSize

    SEC "Final IIS Certificate Expiry Status"
    Show-CertExpiryLegend
    foreach ($b in $finalIisBindings) {
        Show-CertExpiryLine "IIS $($b.SiteName) :$($b.Port)" $b.Cert
    }
    WARN "Old certificates were NOT removed."
    OK "Completed."
}

function Invoke-AdfsReplace {
    SEC "ADFS Pre-Check"

    foreach ($cmd in @("Get-AdfsSslCertificate", "Set-AdfsSslCertificate", "Get-AdfsCertificate", "Set-AdfsCertificate")) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            ERR "ADFS cmdlet not found: $cmd"
            exit
        }
    }
    OK "ADFS cmdlets available."

    SEC "Current ADFS Certificates"
    $ssl = Get-AdfsSslCertificate
    Write-Host "ADFS SSL certificate binding:"
    $ssl | Format-List
    if ($ssl.CertificateHash) { Show-CertSummary "Resolved ADFS SSL certificate:" (Get-LocalMachineCertByThumbprint $ssl.CertificateHash) }

    $svc = Get-AdfsCertificate -CertificateType Service-Communications
    Write-Host ""
    Write-Host "ADFS Service-Communications certificate:"
    $svc | Format-List
    if ($svc.Thumbprint) { Show-CertSummary "Resolved ADFS Service-Communications certificate:" (Get-LocalMachineCertByThumbprint $svc.Thumbprint) }

    SEC "ADFS Certificate Expiry Status"
    Show-CertExpiryLegend
    if ($ssl.CertificateHash) {
        Show-CertExpiryLine "ADFS SSL" (Get-LocalMachineCertByThumbprint $ssl.CertificateHash)
    }
    if ($svc.Thumbprint) {
        Show-CertExpiryLine "ADFS Service-Comm" (Get-LocalMachineCertByThumbprint $svc.Thumbprint)
    }

    $pfx = Get-NewPfxPreview

    SEC "Final Confirmation"
    Write-Host "This will IMPORT the PFX and update:"
    Write-Host "1. ADFS Service-Communications certificate"
    Write-Host "2. ADFS SSL certificate binding"
    Write-Host "ADFS service will be restarted."
    Write-Host "Old certificates will NOT be removed."
    $confirm = Read-Host "Type APPLY to import and assign"
    if ($confirm -ne "APPLY") { WARN "Cancelled. No changes made."; exit }

    Require-AdministratorForApply

    try {
        $imported = Import-PfxToLocalMachineMy $pfx.File $pfx.Password $pfx.Cert
        OK "Certificate ready in LocalMachine\My: $($imported.Thumbprint)"

        Set-AdfsCertificate -Thumbprint $imported.Thumbprint -CertificateType Service-Communications
        Set-AdfsSslCertificate -Thumbprint $imported.Thumbprint
        Restart-Service adfssrv -Force

        OK "ADFS certificates updated and service restarted."
    } catch {
        ERR "ADFS update failed: $($_.Exception.Message)"
        exit
    }

    SEC "Final ADFS Verification"
    $finalAdfsSsl = Get-AdfsSslCertificate
    $finalAdfsSvc = Get-AdfsCertificate -CertificateType Service-Communications
    $finalAdfsSsl | Format-List
    $finalAdfsSvc | Format-List

    SEC "Final ADFS Certificate Expiry Status"
    Show-CertExpiryLegend
    if ($finalAdfsSsl.CertificateHash) {
        Show-CertExpiryLine "ADFS SSL" (Get-LocalMachineCertByThumbprint $finalAdfsSsl.CertificateHash)
    }
    if ($finalAdfsSvc.Thumbprint) {
        Show-CertExpiryLine "ADFS Service-Comm" (Get-LocalMachineCertByThumbprint $finalAdfsSvc.Thumbprint)
    }
    WARN "Old certificates were NOT removed."
    OK "Completed."
}

function Invoke-WapReplace {
    SEC "WAP Pre-Check"

    foreach ($cmd in @("Get-WebApplicationProxySslCertificate", "Set-WebApplicationProxySslCertificate", "Install-WebApplicationProxy")) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            ERR "WAP cmdlet not found: $cmd"
            exit
        }
    }
    OK "WAP cmdlets available."

    $hasIIS = $false
    $targetIisBindings = @()
    if (Get-Module -ListAvailable WebAdministration) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $hasIIS = $true
        OK "IIS module also available on WAP server. IIS 443 bindings can also be updated."
    } else {
        WARN "IIS module not found on WAP server. IIS binding update will be skipped."
    }

    SEC "Current WAP Certificate"
    $wapSsl = Get-WebApplicationProxySslCertificate
    $wapSsl | Format-List
    if ($wapSsl.Thumbprint) { Show-CertSummary "Resolved WAP SSL certificate:" (Get-LocalMachineCertByThumbprint $wapSsl.Thumbprint) }
    elseif ($wapSsl.CertificateHash) { Show-CertSummary "Resolved WAP SSL certificate:" (Get-LocalMachineCertByThumbprint $wapSsl.CertificateHash) }

    SEC "WAP Certificate Expiry Status"
    Show-CertExpiryLegend
    if ($wapSsl.Thumbprint) {
        Show-CertExpiryLine "WAP SSL" (Get-LocalMachineCertByThumbprint $wapSsl.Thumbprint)
    }
    elseif ($wapSsl.CertificateHash) {
        Show-CertExpiryLine "WAP SSL" (Get-LocalMachineCertByThumbprint $wapSsl.CertificateHash)
    }

    if ($hasIIS) {
        SEC "Current IIS Certificates On WAP"
        $httpsBindings = @(Get-IisHttpsBindings)
        if ($httpsBindings.Count -gt 0) {
            $httpsBindings | Select-Object SiteName, BindingInfo, Port, HostName, Thumbprint, Expires | Format-Table -AutoSize

            SEC "WAP Local IIS Certificate Expiry Status"
            Show-CertExpiryLegend
            foreach ($b in $httpsBindings) {
                Show-CertExpiryLine "IIS $($b.SiteName) :$($b.Port)" $b.Cert
            }

            $targetIisBindings = @($httpsBindings | Where-Object { $_.Port -eq "443" })
            $skipped = @($httpsBindings | Where-Object { $_.Port -ne "443" })
            if ($skipped.Count -gt 0) {
                WARN "Skipping non-443 HTTPS bindings. These will NOT be changed:"
                $skipped | Select-Object SiteName, BindingInfo, Port, HostName, Thumbprint, Expires | Format-Table -AutoSize
            }
        } else {
            WARN "No IIS HTTPS bindings found on WAP server."
        }
    }

    $pfx = Get-NewPfxPreview

    if ($targetIisBindings.Count -gt 0) {
        SEC "WAP IIS 443 Coverage Check"
        $requiredNames = $targetIisBindings.HostName |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique

        $missing = @()
        foreach ($name in $requiredNames) {
            if (Test-Covered $name $pfx.Cert $pfx.Sans) { OK $name }
            else { ERR "$name missing"; $missing += $name }
        }

        if ($missing.Count -gt 0) {
            ERR "New certificate does not cover all WAP IIS 443 binding hostnames. Stop."
            exit
        }
    }

    SEC "Detect Federation Service Name"
    $detectedFedName = $null
    if (Get-Command Get-WebApplicationProxyConfiguration -ErrorAction SilentlyContinue) {
        $wapConfig = Get-WebApplicationProxyConfiguration -ErrorAction SilentlyContinue
        $detectedFedName = $wapConfig.FederationServiceName
    }

    if ($detectedFedName) {
        Write-Host "Detected Federation Service Name: $detectedFedName"
        $fedNameInput = Read-Host "Press ENTER to use detected value, or type another Federation Service Name"
        if ([string]::IsNullOrWhiteSpace($fedNameInput)) { $fedName = $detectedFedName }
        else { $fedName = $fedNameInput.Trim() }
    } else {
        $fedName = Read-Host "Enter Federation Service Name"
    }

    if ([string]::IsNullOrWhiteSpace($fedName)) {
        ERR "Federation Service Name cannot be blank."
        exit
    }

    SEC "Final Confirmation"
    Write-Host "This will IMPORT the PFX and:"
    Write-Host "1. Set the Web Application Proxy SSL certificate"
    Write-Host "2. Reinitialize WAP trust using Federation Service Name: $fedName"
    Write-Host "3. Restart the Web Application Proxy service"
    if ($targetIisBindings.Count -gt 0) {
        Write-Host "4. Replace local IIS HTTPS binding certificates on port 443 ONLY"
        Write-Host "5. Run iisreset"
    }
    Write-Host "Old certificates will NOT be removed."
    $confirm = Read-Host "Type APPLY to import and assign"
    if ($confirm -ne "APPLY") { WARN "Cancelled. No changes made."; exit }

    Require-AdministratorForApply

    try {
        $imported = Import-PfxToLocalMachineMy $pfx.File $pfx.Password $pfx.Cert
        OK "Certificate ready in LocalMachine\My: $($imported.Thumbprint)"

        Set-WebApplicationProxySslCertificate -Thumbprint $imported.Thumbprint
        OK "WAP SSL certificate assigned."

        if ($targetIisBindings.Count -gt 0) {
            SEC "Update Local IIS 443 Bindings On WAP"
            foreach ($b in $targetIisBindings) {
                $b.Binding.RemoveSslCertificate()
                $b.Binding.AddSslCertificate($imported.Thumbprint, "My")
                OK "Updated IIS 443 binding: $($b.SiteName) / $($b.BindingInfo)"
            }
            SEC "IIS Reset"
            iisreset
        }

        SEC "WAP Trust Reinitialization"
        Install-WebApplicationProxy -CertificateThumbprint $imported.Thumbprint -FederationServiceName $fedName

        SEC "Restart WAP Service"
        Restart-Service "appproxysvc" -Force

        OK "WAP trust reinitialized and Web Application Proxy service restarted."
    } catch {
        ERR "WAP update/reinitialization failed: $($_.Exception.Message)"
        exit
    }

    SEC "Final WAP Verification"
    $finalWapSsl = Get-WebApplicationProxySslCertificate
    $finalWapSsl | Format-List

    SEC "Final WAP Certificate Expiry Status"
    Show-CertExpiryLegend
    if ($finalWapSsl.Thumbprint) {
        Show-CertExpiryLine "WAP SSL" (Get-LocalMachineCertByThumbprint $finalWapSsl.Thumbprint)
    }
    elseif ($finalWapSsl.CertificateHash) {
        Show-CertExpiryLine "WAP SSL" (Get-LocalMachineCertByThumbprint $finalWapSsl.CertificateHash)
    }

    if ($hasIIS) {
        SEC "Final IIS Verification On WAP"
        $finalWapIisBindings = @(Get-IisHttpsBindings)
        $finalWapIisBindings | Select-Object SiteName, BindingInfo, Port, HostName, Thumbprint, Expires | Format-Table -AutoSize

        SEC "Final WAP Local IIS Certificate Expiry Status"
        Show-CertExpiryLegend
        foreach ($b in $finalWapIisBindings) {
            Show-CertExpiryLine "IIS $($b.SiteName) :$($b.Port)" $b.Cert
        }
    }
    WARN "Old certificates were NOT removed."
    OK "Completed."
}

function Invoke-ExchangeReplace {
    SEC "Exchange Pre-Check"

    foreach ($cmd in @("Get-ExchangeCertificate", "Import-ExchangeCertificate", "Enable-ExchangeCertificate")) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            ERR "Exchange cmdlet not found: $cmd. Run from Exchange Management Shell."
            exit
        }
    }
    OK "Exchange cmdlets available."

    SEC "Current Exchange Certificates"
    $now = Get-Date
    $exchangeCerts = @(Get-ExchangeCertificate | Sort-Object NotAfter)

    $exchangeCerts |
        Select-Object Subject, Thumbprint, Services, NotAfter, Status, IsSelfSigned |
        Format-Table -AutoSize

    SEC "Exchange Certificate Expiry Status"
    Show-CertExpiryLegend
    foreach ($cert in $exchangeCerts) {
        if ($cert.Services.ToString() -ne "None") {
            Show-CertExpiryLine "Exchange $($cert.Services)" $cert
        }
    }

    $oldCert = $exchangeCerts |
        Where-Object {
            $_.Services.ToString() -ne "None" -and
            $_.IsSelfSigned -eq $false -and
            $_.NotAfter -le $now.AddDays($ExpiryWarningDays)
        } |
        Sort-Object NotAfter |
        Select-Object -First 1

    if (-not $oldCert) {
        WARN "No public Exchange certificate with assigned services expires within $ExpiryWarningDays days."
        Write-Host "You can still continue by selecting the currently assigned public cert manually."

        $candidates = @($exchangeCerts | Where-Object { $_.Services.ToString() -ne "None" -and $_.IsSelfSigned -eq $false } | Sort-Object NotAfter)
        if ($candidates.Count -eq 0) {
            ERR "No assigned public Exchange certificate found. Stop."
            exit
        }

        for ($i = 0; $i -lt $candidates.Count; $i++) {
            Write-Host "$($i + 1). $($candidates[$i].Subject) | $($candidates[$i].Thumbprint) | Services: $($candidates[$i].Services) | Expires: $($candidates[$i].NotAfter)"
        }

        $sel = Read-Host "Choose current certificate number to replace/clone services from"
        if (-not ($sel -as [int]) -or [int]$sel -lt 1 -or [int]$sel -gt $candidates.Count) {
            ERR "Invalid selection."
            exit
        }
        $oldCert = $candidates[[int]$sel - 1]
    }

    $oldDays = [math]::Floor(($oldCert.NotAfter - $now).TotalDays)
    $oldServices = $oldCert.Services.ToString()
    $requiredNames = $oldCert.CertificateDomains | ForEach-Object { $_.ToString().ToLower() } | Sort-Object -Unique

    WARN "Current Exchange cert selected for replacement/service cloning:"
    Write-Host "Subject    : $($oldCert.Subject)"
    Write-Host "Thumbprint : $($oldCert.Thumbprint)"
    Write-Host "Expires    : $($oldCert.NotAfter)"
    Write-Host "Days Left  : $oldDays"
    Write-Host "Services   : $oldServices"
    Write-Host "Covers:"
    $requiredNames | ForEach-Object { Write-Host " - $_" }

    $pfx = Get-NewPfxPreview

    if ($pfx.Cert.NotAfter -le $oldCert.NotAfter) {
        ERR "New certificate is not newer than selected Exchange certificate. Stop."
        exit
    }

    SEC "Exchange Coverage Check"
    $missing = @()
    foreach ($name in $requiredNames) {
        if (Test-Covered $name $pfx.Cert $pfx.Sans) { OK $name }
        else { ERR "$name missing"; $missing += $name }
    }

    if ($missing.Count -gt 0) {
        ERR "New certificate does not cover all names from the selected Exchange certificate. Stop."
        exit
    }

    SEC "Final Confirmation"
    Write-Host "This will IMPORT the PFX using Exchange and ASSIGN it to the SAME Exchange services: $oldServices"
    Write-Host "It does NOT directly edit IIS bindings and does NOT remove the old certificate."
    Write-Host "Old thumbprint: $($oldCert.Thumbprint)"
    $confirm = Read-Host "Type APPLY to import and assign"
    if ($confirm -ne "APPLY") { WARN "Cancelled. No changes made."; exit }

    Require-AdministratorForApply

    try {
        $existingExchangeCert = Get-ExchangeCertificate -Thumbprint $pfx.Cert.Thumbprint -ErrorAction SilentlyContinue
        if ($existingExchangeCert) {
            WARN "Certificate already exists in Exchange certificate store. Reusing it."
            $imported = $existingExchangeCert
        } else {
            $imported = Import-ExchangeCertificate `
                -FileData ([System.IO.File]::ReadAllBytes($pfx.File.FullName)) `
                -Password $pfx.Password `
                -PrivateKeyExportable $true
        }

        OK "Exchange certificate ready: $($imported.Thumbprint)"
        Enable-ExchangeCertificate -Thumbprint $imported.Thumbprint -Services $oldServices -Force
        OK "New certificate assigned to Exchange services: $oldServices"
    } catch {
        ERR "Exchange update failed: $($_.Exception.Message)"
        exit
    }

    SEC "Final Exchange Verification"
    $finalExchangeCert = Get-ExchangeCertificate -Thumbprint $imported.Thumbprint
    $finalExchangeCert |
        Select-Object Subject, Thumbprint, Services, NotAfter, Status |
        Format-List

    SEC "Final Exchange Certificate Expiry Status"
    Show-CertExpiryLegend
    Show-CertExpiryLine "Exchange $($finalExchangeCert.Services)" $finalExchangeCert

    WARN "Old Exchange certificate was NOT removed: $($oldCert.Thumbprint)"
    OK "Completed."
}


function Invoke-RdsReplace {
    SEC "RDS Pre-Check"

    foreach ($cmd in @("Get-RDCertificate", "Set-RDCertificate")) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            ERR "RDS cmdlet not found: $cmd"
            exit
        }
    }
    OK "RDS cmdlets available."

    SEC "Detect RD Connection Broker"

$broker = $null

try {
    if (Get-Command Get-RDServer -ErrorAction SilentlyContinue) {

        $rdServers = @(Get-RDServer -ErrorAction Stop)

        $brokerServer = $rdServers |
            Where-Object { $_.Roles -match "RDS-CONNECTION-BROKER" } |
            Select-Object -First 1

        if ($brokerServer) {
            $broker = $brokerServer.Server
            OK "Detected RD Connection Broker: $broker"
        }
    }
}
catch {
    WARN "Automatic RD Connection Broker detection failed."
}

if ([string]::IsNullOrWhiteSpace($broker)) {
    WARN "Could not automatically detect RD Connection Broker."
    $brokerInput = Read-Host "Enter RD Connection Broker FQDN, or press ENTER for local server"

    if ([string]::IsNullOrWhiteSpace($brokerInput)) {
        $broker = $env:COMPUTERNAME
    }
    else {
        $broker = $brokerInput.Trim()
    }
}

Write-Host "Using RD Connection Broker: $broker"

    SEC "Current RDS Deployment Certificates"
    try {
        $rdsCerts = @(Get-RDCertificate -ConnectionBroker $broker -ErrorAction Stop)
        if ($rdsCerts.Count -gt 0) {
            $rdsCerts | Format-Table Role, Level, Subject, IssuedTo, ExpiresOn, Thumbprint -AutoSize

            SEC "RDS Certificate Expiry Status"
            Show-CertExpiryLegend
            foreach ($rc in $rdsCerts) {
                $label = "RDS $($rc.Role)"
                if ($rc.Thumbprint) {
                    $resolvedCert = Get-LocalMachineCertByThumbprint $rc.Thumbprint
                    if ($resolvedCert) {
                        Show-CertExpiryLine $label $resolvedCert
                    }
                    elseif ($rc.ExpiresOn) {
                        $days = [math]::Floor(($rc.ExpiresOn - (Get-Date)).TotalDays)
                        $color = Get-RoleHealthColor $days
                        Write-Host ("{0,-35} Expires: {1} | Days Left: {2} | Thumbprint: {3}" -f $label, $rc.ExpiresOn, $days, $rc.Thumbprint) -ForegroundColor $color
                    }
                }
                elseif ($rc.ExpiresOn) {
                    $days = [math]::Floor(($rc.ExpiresOn - (Get-Date)).TotalDays)
                    $color = Get-RoleHealthColor $days
                    Write-Host ("{0,-35} Expires: {1} | Days Left: {2}" -f $label, $rc.ExpiresOn, $days) -ForegroundColor $color
                }
            }
        } else {
            WARN "No RDS deployment certificates returned by Get-RDCertificate."
        }
    } catch {
        ERR "Failed to read RDS deployment certificates from broker '$broker': $($_.Exception.Message)"
        exit
    }

    SEC "Current Local RDP-Tcp Listener Certificate"
    $listener = $null
    try {
        $listener = Get-WmiObject `
            -Namespace "root\cimv2\terminalservices" `
            -Class "Win32_TSGeneralSetting" `
            -Filter "TerminalName='RDP-tcp'" `
            -ErrorAction Stop

        $listenerThumb = ($listener.SSLCertificateSHA1Hash -replace " ", "").ToUpper()
        Write-Host "RDP-Tcp Thumbprint : $listenerThumb"
        if ($listenerThumb) {
            Show-CertSummary "Resolved local RDP-Tcp listener certificate:" (Get-LocalMachineCertByThumbprint $listenerThumb)
        }
    } catch {
        WARN "Could not read local RDP-Tcp listener certificate: $($_.Exception.Message)"
    }

    $pfx = Get-NewPfxPreview

    SEC "RDS Coverage Notice"
    Write-Host "RDS deployment roles normally require a certificate that covers the public/internal names used by RD Web, RD Gateway and RD Connection Broker."
    Write-Host "This script shows the certificate details but does not enforce name matching for RDS because deployments vary."

    SEC "Final Confirmation"
    $rolesToUpdate = @(
        $rdsCerts |
        Where-Object { $_.Role -and ($_.Thumbprint -or $_.ExpiresOn) } |
        Select-Object -ExpandProperty Role -Unique
    )

    if ($rolesToUpdate.Count -eq 0) {
        ERR "No existing assigned RDS certificate roles found. Nothing to replace."
        exit
    }

    Write-Host "This will IMPORT/APPLY the PFX to existing RDS deployment roles on broker: $broker"
    Write-Host "Roles that will be updated:"
    $rolesToUpdate | ForEach-Object { Write-Host " - $_" }
    Write-Host ""
    Write-Host "The local RDP-Tcp listener certificate will be updated only if an existing assigned certificate is detected."
    Write-Host "Old certificates will NOT be removed."

    SEC "Detect Existing RDP-Tcp Listener Certificate"

$updateListener = $false

try {

    $rdpSetting = Get-WmiObject `
        -Namespace "root\cimv2\terminalservices" `
        -Class "Win32_TSGeneralSetting" `
        -Filter "TerminalName='RDP-tcp'"

    $existingHash = ($rdpSetting.SSLCertificateSHA1Hash -replace " ", "").ToUpper()

    if (-not [string]::IsNullOrWhiteSpace($existingHash)) {

        $existingRdpCert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $existingHash } |
            Select-Object -First 1

        if ($existingRdpCert) {

            Show-CertSummary "Existing RDP-Tcp listener certificate:" $existingRdpCert

            $updateListener = $true
            OK "Existing RDP listener certificate detected. It WILL be updated automatically."
        }
        else {

            WARN "RDP listener has a configured thumbprint but certificate was not found in LocalMachine\My."
        }
    }
    else {

        WARN "No custom RDP listener certificate detected. Listener update will be skipped."
    }

}
catch {

    WARN "Could not detect RDP listener certificate. Listener update will be skipped."
}
    $confirm = Read-Host "Type APPLY to import and assign"
    if ($confirm -ne "APPLY") { WARN "Cancelled. No changes made."; exit }

    Require-AdministratorForApply

    try {
        foreach ($rdsRole in $rolesToUpdate) {
            try {
                Set-RDCertificate `
                    -Role $rdsRole `
                    -ImportPath $pfx.File.FullName `
                    -Password $pfx.Password `
                    -ConnectionBroker $broker `
                    -Force `
                    -ErrorAction Stop

                OK "Updated RDS deployment role: $rdsRole"
            } catch {
                WARN "Could not update RDS deployment role $rdsRole : $($_.Exception.Message)"
            }
        }

        if ($updateListener) {
            SEC "Update Local RDP-Tcp Listener"

            $imported = Import-PfxToLocalMachineMy $pfx.File $pfx.Password $pfx.Cert
            $thumb = ($imported.Thumbprint -replace " ", "").ToUpper()

            $rdpSetting = Get-WmiObject `
                -Namespace "root\cimv2\terminalservices" `
                -Class "Win32_TSGeneralSetting" `
                -Filter "TerminalName='RDP-tcp'" `
                -ErrorAction Stop

            Set-WmiInstance -Path $rdpSetting.__PATH -Arguments @{
                SSLCertificateSHA1Hash = $thumb
            } | Out-Null

            OK "Updated local RDP-Tcp listener certificate: $thumb"
            WARN "A Remote Desktop Services restart or server reboot may be required for the listener change to fully apply."
        }
    } catch {
        ERR "RDS update failed: $($_.Exception.Message)"
        exit
    }

    SEC "Final RDS Deployment Verification"
    try {
        $finalRdsCerts = @(Get-RDCertificate -ConnectionBroker $broker -ErrorAction Stop)
        $finalRdsCerts | Format-Table Role, Level, Subject, IssuedTo, ExpiresOn, Thumbprint -AutoSize

        SEC "Final RDS Certificate Expiry Status"
        Show-CertExpiryLegend
        foreach ($rc in $finalRdsCerts) {
            $label = "RDS $($rc.Role)"
            if ($rc.Thumbprint) {
                $resolvedCert = Get-LocalMachineCertByThumbprint $rc.Thumbprint
                if ($resolvedCert) {
                    Show-CertExpiryLine $label $resolvedCert
                }
                elseif ($rc.ExpiresOn) {
                    $days = [math]::Floor(($rc.ExpiresOn - (Get-Date)).TotalDays)
                    $color = Get-RoleHealthColor $days
                    Write-Host ("{0,-35} Expires: {1} | Days Left: {2} | Thumbprint: {3}" -f $label, $rc.ExpiresOn, $days, $rc.Thumbprint) -ForegroundColor $color
                }
            }
            elseif ($rc.ExpiresOn) {
                $days = [math]::Floor(($rc.ExpiresOn - (Get-Date)).TotalDays)
                $color = Get-RoleHealthColor $days
                Write-Host ("{0,-35} Expires: {1} | Days Left: {2}" -f $label, $rc.ExpiresOn, $days) -ForegroundColor $color
            }
        }
    } catch {
        WARN "Could not verify RDS deployment certificates: $($_.Exception.Message)"
    }

    if ($updateListener) {
        SEC "Final RDP-Tcp Listener Verification"
        try {
            Get-WmiObject `
                -Namespace "root\cimv2\terminalservices" `
                -Class "Win32_TSGeneralSetting" `
                -Filter "TerminalName='RDP-tcp'" |
                Select-Object TerminalName, SSLCertificateSHA1Hash |
                Format-List
        } catch {
            WARN "Could not verify RDP-Tcp listener certificate: $($_.Exception.Message)"
        }
    }

    WARN "Old certificates were NOT removed."
    OK "Completed."
}

Show-Banner
Show-AdminNotice
Write-Host ""
Write-Host "Recommended if blocked by execution policy:" -ForegroundColor White
Write-Host "  Set-ExecutionPolicy Bypass -Scope Process -Force" -ForegroundColor Yellow
Write-Host "Place the NEW .pfx/.p12 certificate in the SAME folder as this script before continuing." -ForegroundColor White
Write-Host "Old certificates are NOT removed automatically." -ForegroundColor DarkGray
Write-Host ""

$role = Select-Role

switch ($role) {
    "IIS"      { Invoke-IisReplace }
    "ADFS"     { Invoke-AdfsReplace }
    "WAP"      { Invoke-WapReplace }
    "EXCHANGE" { Invoke-ExchangeReplace }
    "RDS"      { Invoke-RdsReplace }
}
