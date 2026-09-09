# PowerShell script to sign driver
# Requires Administrator privileges
# Called non-interactively by build-package.bat: no pause, strict exit codes
#   exit 1 = signing step failed
#   exit 2 = signature self-check failed (signed but Status not Valid)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Ceasefire Driver Signing Tool (PowerShell)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[SIGN-ERROR] This script requires administrator privileges" -ForegroundColor Red
    Write-Host "[SIGN-ERROR] Re-run build-package.bat from an elevated (administrator) console" -ForegroundColor Red
    exit 1
}

$driverPath = Join-Path $PSScriptRoot "bin\x64\Release\CeasefireDriver.sys"
$certName = "CeasefireTestCert"

Write-Host "Driver path: $driverPath"
Write-Host ""

# Check if driver file exists
if (-not (Test-Path $driverPath)) {
    Write-Host "[SIGN-ERROR] Driver file not found: $driverPath" -ForegroundColor Red
    Write-Host "[SIGN-ERROR] Compile the driver first" -ForegroundColor Red
    exit 1
}

# Step 1: Find or create the code signing certificate
Write-Host "[1/4] Looking for existing code signing certificate..." -ForegroundColor Yellow
# Reuse an existing valid certificate with a private key first; creating a new
# one on every run litters the store (dozens of orphaned certs) and produces
# signatures the test machine does not trust.
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq "CN=$certName" -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if ($cert) {
    Write-Host "Reusing existing certificate: $($cert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "No usable certificate found, creating a new one..." -ForegroundColor Yellow
    try {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$certName" -CertStoreLocation Cert:\CurrentUser\My
        Write-Host "Certificate created: $($cert.Thumbprint)" -ForegroundColor Green
    } catch {
        Write-Host "[SIGN-ERROR] Failed to create certificate: $_" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# Step 2: Export certificate
Write-Host "[2/4] Exporting certificate..." -ForegroundColor Yellow
$cerPath = Join-Path $PSScriptRoot "$certName.cer"
try {
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host "Certificate exported to: $cerPath" -ForegroundColor Green
} catch {
    Write-Host "[SIGN-ERROR] Failed to export certificate: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 3: Install certificate to Trusted Root
Write-Host "[3/4] Installing certificate to Trusted Root store..." -ForegroundColor Yellow
try {
    Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Write-Host "Certificate installed successfully" -ForegroundColor Green
} catch {
    Write-Host "[SIGN-ERROR] Failed to install certificate: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 4: Sign the driver
Write-Host "[4/4] Signing driver..." -ForegroundColor Yellow
try {
    Set-AuthenticodeSignature -FilePath $driverPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256 | Out-Null
    Write-Host "Driver signed successfully" -ForegroundColor Green
} catch {
    Write-Host "[SIGN-WARN] Signing with timestamp failed, trying without timestamp..." -ForegroundColor Yellow
    try {
        Set-AuthenticodeSignature -FilePath $driverPath -Certificate $cert -HashAlgorithm SHA256 | Out-Null
        Write-Host "Driver signed successfully (without timestamp)" -ForegroundColor Green
    } catch {
        Write-Host "[SIGN-ERROR] Failed to sign driver: $_" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# Step 5: Self-check - the signing call succeeding does not guarantee a valid
# signature on the file. Verify before reporting success.
$sig = Get-AuthenticodeSignature -FilePath $driverPath
if ($sig.Status -ne 'Valid') {
    Write-Host "[SIGN-ERROR] Signature self-check failed: Status=$($sig.Status) ($($sig.StatusMessage))" -ForegroundColor Red
    Write-Host "[SIGN-ERROR] File: $driverPath" -ForegroundColor Red
    exit 2
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Driver Signing Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Signed file : $driverPath"
Write-Host "Certificate : $certName"
Write-Host "Thumbprint  : $($cert.Thumbprint)"
Write-Host "Cert file   : $cerPath"
Write-Host "Signature   : Valid (verified via Get-AuthenticodeSignature)"
Write-Host ""
