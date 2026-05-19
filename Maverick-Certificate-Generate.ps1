# IMPORTANT:
# If PowerShell blocks this script, run the following command first:
# Set-ExecutionPolicy Bypass -Scope Process -Force

<#
.SYNOPSIS
    Manual DNS-01 Let's Encrypt wildcard certificate generator.

.DESCRIPTION
    This script generates a wildcard certificate for a domain using Let's Encrypt / ACME via Posh-ACME.
    It uses manual DNS TXT validation, then copies the generated PFX to the same folder as this script.

.NOTES
    - No EXE is required.
    - Internet access is required.
    - DNS access is required to create the TXT record shown during validation.
    - Wildcard certificates require DNS-01 validation.
    - Manual DNS validation is not ideal for unattended renewals. For automation, use a DNS API plugin later.
#>

cls

$ScriptName    = "Maverick Let's Encrypt Wildcard Generator"
$ScriptVersion = "1.0.1"
$ScriptAuthor  = "Maverick"

$ErrorActionPreference = "Stop"

function Write-Header {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " $ScriptName" -ForegroundColor Cyan
    Write-Host " Version: $ScriptVersion" -ForegroundColor DarkCyan
    Write-Host " Author : $ScriptAuthor" -ForegroundColor DarkCyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-RequiredValue {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [string]$DefaultValue
    )

    do {
        if ([string]::IsNullOrWhiteSpace($DefaultValue)) {
            $value = Read-Host $Prompt
        } else {
            $value = Read-Host "$Prompt [$DefaultValue]"
            if ([string]::IsNullOrWhiteSpace($value)) { $value = $DefaultValue }
        }

        $value = $value.Trim()
    } while ([string]::IsNullOrWhiteSpace($value))

    return $value
}

function Normalize-Domain {
    param([Parameter(Mandatory=$true)][string]$Domain)

    $clean = $Domain.Trim().ToLower()
    $clean = $clean -replace '^https?://', ''
    $clean = $clean -replace '^\*\.', ''
    $clean = $clean.TrimEnd('/')
    $clean = $clean.TrimEnd('.')

    if ($clean -notmatch '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$') {
        throw "Invalid domain format: $Domain"
    }

    return $clean
}

function Ensure-PoshACME {
    Write-Host "Checking Posh-ACME module..." -ForegroundColor Yellow

    $module = Get-Module -ListAvailable -Name Posh-ACME | Sort-Object Version -Descending | Select-Object -First 1

    if (-not $module) {
        Write-Host ""
        Write-Host "Required PowerShell module not found: Posh-ACME" -ForegroundColor Yellow
        Write-Host "This module is required to generate free Let's Encrypt certificates." -ForegroundColor Cyan
        Write-Host "It will be installed from the PowerShell Gallery for the current user only." -ForegroundColor DarkGray
        Write-Host ""

        $installConfirm = Read-Host "Do you want to install Posh-ACME now? (Y/N)"

        if ($installConfirm -notmatch '^[Yy]$') {
            Write-Host ""
            Write-Host "Cannot continue without Posh-ACME. No changes were made." -ForegroundColor Red
            exit 1
        }

        try {
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                Write-Host "NuGet package provider is required." -ForegroundColor Yellow
                $nugetConfirm = Read-Host "Do you want to install NuGet package provider now? (Y/N)"
                if ($nugetConfirm -notmatch '^[Yy]$') {
                    Write-Host "Cannot continue without NuGet package provider." -ForegroundColor Red
                    exit 1
                }

                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }

            Install-Module -Name Posh-ACME -Scope CurrentUser -Force -AllowClobber

            Write-Host ""
            Write-Host "Posh-ACME installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host ""
            Write-Host "Failed to install Posh-ACME." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            throw
        }
    }

    Import-Module Posh-ACME -Force
    $loaded = Get-Module Posh-ACME
    Write-Host "Loaded Posh-ACME version $($loaded.Version)" -ForegroundColor Green
}

function Get-PACertOutputFolder {
    param($CertObject)

    $candidateProps = @('Folder','CertFolder','OrderFolder')

    foreach ($prop in $candidateProps) {
        if ($CertObject.PSObject.Properties.Name -contains $prop) {
            $path = $CertObject.$prop
            if ($path -and (Test-Path $path)) { return $path }
        }
    }

    $fileProps = @('PfxFullChain','PfxFile','FullChainFile','CertFile')
    foreach ($prop in $fileProps) {
        if ($CertObject.PSObject.Properties.Name -contains $prop) {
            $file = $CertObject.$prop
            if ($file -and (Test-Path $file)) { return (Split-Path -Parent $file) }
        }
    }

    return $null
}

function Copy-CertFilesToScriptFolder {
    param(
        [Parameter(Mandatory=$true)]$CertObject,
        [Parameter(Mandatory=$true)][string]$Domain,
        [Parameter(Mandatory=$true)][string]$DestinationFolder
    )

    $safeDomain = $Domain -replace '[^a-zA-Z0-9.-]', '_'
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $sourceFolder = Get-PACertOutputFolder -CertObject $CertObject

    $candidateFiles = New-Object System.Collections.Generic.List[string]

    foreach ($prop in @('PfxFullChain','PfxFile','FullChainFile','CertFile','ChainFile')) {
        if ($CertObject.PSObject.Properties.Name -contains $prop) {
            $file = $CertObject.$prop
            if ($file -and (Test-Path $file)) { [void]$candidateFiles.Add($file) }
        }
    }

    if ($sourceFolder -and (Test-Path $sourceFolder)) {
        Get-ChildItem -Path $sourceFolder -File -Include *.pfx,*.cer,*.crt,*.pem -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            if ($candidateFiles -notcontains $_.FullName) { [void]$candidateFiles.Add($_.FullName) }
        }
    }

    $pfxSource = $candidateFiles |
        Where-Object { $_ -match '\.pfx$' } |
        Sort-Object { if ($_ -match 'fullchain') { 0 } else { 1 } }, Name |
        Select-Object -First 1

    if (-not $pfxSource) {
        throw "Certificate was generated, but no PFX file was found in the Posh-ACME output folder."
    }

    $destPfx = Join-Path $DestinationFolder "$safeDomain-wildcard-$timestamp.pfx"
    Copy-Item -Path $pfxSource -Destination $destPfx -Force

    Write-Host ""
    Write-Host "PFX copied successfully:" -ForegroundColor Green
    Write-Host $destPfx -ForegroundColor White

    foreach ($extra in $candidateFiles | Where-Object { $_ -ne $pfxSource -and ($_ -match '\.(cer|crt|pem)$') }) {
        try {
            $extraName = "$safeDomain-wildcard-$timestamp-$([IO.Path]::GetFileName($extra))"
            Copy-Item -Path $extra -Destination (Join-Path $DestinationFolder $extraName) -Force
        }
        catch {
            Write-Host "Could not copy extra certificate file: $extra" -ForegroundColor DarkYellow
        }
    }

    return $destPfx
}

function Show-DnsChallengeRecords {
    param(
        [Parameter(Mandatory=$true)]$Authorizations
    )

    Write-Host ""
    Write-Host "Please create the following TXT record(s):" -ForegroundColor Cyan
    Write-Host "------------------------------------------" -ForegroundColor DarkCyan

    foreach ($auth in $Authorizations) {
        if ($auth.status -eq "valid") { continue }

        $dnsName = $auth.DNSId -replace '^\*\.',''
        $recordName = "_acme-challenge.$dnsName"
        $recordValue = Get-KeyAuthorization $auth.DNS01Token -ForDNS

        Write-Host "$recordName -> $recordValue" -ForegroundColor White
    }

    Write-Host "------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "Important:" -ForegroundColor Yellow
    Write-Host "- Add ALL TXT values shown above." -ForegroundColor Yellow
    Write-Host "- If two values use the same name, keep both values. Do not replace the first one." -ForegroundColor Yellow
    Write-Host "- Some DNS panels want only '_acme-challenge' in the Host/Name field." -ForegroundColor Yellow
    Write-Host "- Wait around 1-5 minutes after saving the DNS records." -ForegroundColor Yellow
    Write-Host ""
}

function Invoke-VerificationProgress {
    Write-Host ""
    Write-Host -NoNewline "Verifying DNS records" -ForegroundColor Cyan
    1..3 | ForEach-Object {
        Start-Sleep -Seconds 1
        Write-Host -NoNewline "." -ForegroundColor Cyan
    }
    Write-Host ""
}

function Wait-ForAcmeValidation {
    param(
        [int]$TimeoutSeconds = 180
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        $auths = Get-PAOrder | Get-PAAuthorization

        if (($auths | Where-Object { $_.status -eq "invalid" })) {
            throw "One or more DNS validations failed. Check the TXT records and DNS propagation, then try again."
        }

        if (($auths | Where-Object { $_.status -ne "valid" }).Count -eq 0) {
            return $true
        }

        Write-Host -NoNewline "." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
    }

    throw "Timed out while waiting for Let's Encrypt to validate the DNS records."
}

Write-Header

if (-not (Test-IsAdmin)) {
    Write-Host "Notice: PowerShell is not running as Administrator." -ForegroundColor Yellow
    Write-Host "This is OK for generation/export only." -ForegroundColor Yellow
    Write-Host "Admin is only needed if you later import/install the cert into machine stores or services." -ForegroundColor Yellow
    Write-Host ""
}

$ScriptFolder = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrWhiteSpace($ScriptFolder)) { $ScriptFolder = (Get-Location).Path }

Write-Host "Output folder:" -ForegroundColor Cyan
Write-Host $ScriptFolder -ForegroundColor White
Write-Host ""

try {
    Ensure-PoshACME

    Write-Host ""
    Write-Host "This tool will request a wildcard certificate using manual DNS TXT validation." -ForegroundColor Cyan
    Write-Host "Example: if you enter example.com, the cert will include:" -ForegroundColor Cyan
    Write-Host "  example.com" -ForegroundColor White
    Write-Host "  *.example.com" -ForegroundColor White
    Write-Host ""

    $domainInput = Read-RequiredValue -Prompt "Enter root domain, without wildcard, example: example.com"
    $domain = Normalize-Domain -Domain $domainInput
    $wildcardDomain = "*.$domain"

    $contactEmail = Read-RequiredValue -Prompt "Enter email for Let's Encrypt expiry/account notices" -DefaultValue "admin@$domain"

    Write-Host ""
    Write-Host "Certificate names to request:" -ForegroundColor Cyan
    Write-Host "  $domain" -ForegroundColor White
    Write-Host "  $wildcardDomain" -ForegroundColor White
    Write-Host ""

    $pfxSecret1 = Read-Host "Enter PFX password/secret" -AsSecureString
    $pfxSecret2 = Read-Host "Confirm PFX password/secret" -AsSecureString

    $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxSecret1)
    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxSecret2)
    try {
        $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
        $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
        if ($plain1 -ne $plain2) { throw "PFX passwords do not match. Please run the script again." }
        if ([string]::IsNullOrWhiteSpace($plain1)) { throw "PFX password cannot be empty." }
    }
    finally {
        if ($bstr1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1) }
        if ($bstr2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2) }
    }

    Write-Host ""
    Write-Host "This script will NOT install the certificate into IIS, Exchange, ADFS, WAP, or the Windows certificate store." -ForegroundColor Yellow
    Write-Host "It will only generate/export the PFX and copy it beside the script." -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "Type YES to start the Let's Encrypt order"
    if ($confirm -ne "YES") {
        Write-Host "Cancelled by user." -ForegroundColor Yellow
        exit 0
    }

    Set-PAServer LE_PROD

    if (-not (Get-PAAccount -ErrorAction SilentlyContinue)) {
        New-PAAccount -Contact $contactEmail -AcceptTOS | Out-Null
    }

    $domains = @($domain, $wildcardDomain)

    New-PAOrder `
        -Domain $domains `
        -PfxPassSecure $pfxSecret1 `
        -FriendlyName "Wildcard $domain - Let's Encrypt" `
        -Force | Out-Null

    $auths = Get-PAOrder | Get-PAAuthorization

    Show-DnsChallengeRecords -Authorizations $auths

    $continue = Read-Host "When done entering the DNS record(s), press ENTER to verify, or type C to cancel"
    if ($continue -match '^[Cc]$') {
        Write-Host "Cancelled by user." -ForegroundColor Yellow
        exit 0
    }

    Invoke-VerificationProgress

    $pendingAuths = Get-PAOrder | Get-PAAuthorization | Where-Object { $_.status -ne "valid" }

    foreach ($auth in $pendingAuths) {
        $auth.DNS01Url | Send-ChallengeAck
    }

    Wait-ForAcmeValidation -TimeoutSeconds 180 | Out-Null

    Write-Host ""
    Write-Host "DNS validation successful." -ForegroundColor Green

    $order = Get-PAOrder -Refresh

    if ($order.status -eq "ready") {
        Write-Host "Finalizing certificate order..." -ForegroundColor Cyan
        Submit-OrderFinalize | Out-Null
    }

    $order = Get-PAOrder -Refresh

    if ($order.status -ne "valid") {
        Write-Host "Completing certificate order..." -ForegroundColor Cyan
    }

    $cert = Complete-PAOrder

    if (-not $cert) {
        $cert = Get-PACertificate
    }

    if (-not $cert) {
        throw "Certificate order completed, but no certificate object was returned."
    }

    $copiedPfx = Copy-CertFilesToScriptFolder -CertObject $cert -Domain $domain -DestinationFolder $ScriptFolder

    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
    Write-Host "Use this PFX with your certificate install/renewal toolkit:" -ForegroundColor Green
    Write-Host $copiedPfx -ForegroundColor White
    Write-Host ""
    Write-Host "Remember the PFX password you entered. It is required when importing the certificate." -ForegroundColor Yellow
}
catch {
    Write-Host ""
    Write-Host "FAILED:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "If DNS validation failed, wait a few minutes for TXT propagation and run the script again." -ForegroundColor Yellow
    exit 1
}
