<#
.SYNOPSIS
    Create one AVD per API level for the drift runs.

.DESCRIPTION
    For each API level in $ApiLevels, creates an AVD named ghera<api> with the
    device profile "pixel" and the system image
    system-images;android-<api>;google_apis;x86.
    An AVD that already exists is skipped. A missing system image is reported
    and skipped; install it first with
        sdkmanager "system-images;android-<api>;google_apis;x86"

    avdmanager in cmdline-tools 23.0 needs Java 17, so JAVA_HOME is set to
    C:\Android\jdk17 while the script runs and restored afterwards.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\create_avds.ps1
#>
[CmdletBinding()]
param(
    [int[]]$ApiLevels = @(22, 25, 27, 28, 30, 33, 34)
)

$ErrorActionPreference = 'Stop'

$SdkRoot   = 'C:\Android\Sdk'
$Jdk17Home = 'C:\Android\jdk17'
$Device    = 'pixel'
$Tag       = 'google_apis'
$Abi       = 'x86'

$avdmanager = Join-Path $SdkRoot 'cmdline-tools\latest\bin\avdmanager.bat'
if (-not (Test-Path $avdmanager)) { throw "avdmanager not found: $avdmanager" }
if (-not (Test-Path $Jdk17Home))  { throw "JDK 17 not found: $Jdk17Home" }

$savedJavaHome = $env:JAVA_HOME
$savedSdkRoot  = $env:ANDROID_SDK_ROOT
$env:JAVA_HOME        = $Jdk17Home
$env:ANDROID_SDK_ROOT = $SdkRoot
try {
    # "list avd -c" prints one AVD name per line.
    $existing = @(& $avdmanager list avd -c 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    foreach ($api in $ApiLevels) {
        $name    = "ghera$api"
        $package = "system-images;android-$api;$Tag;$Abi"
        $imageDir = Join-Path $SdkRoot "system-images\android-$api\$Tag\$Abi"

        if ($existing -contains $name) {
            Write-Host "skip   $name (already exists)"
            continue
        }
        if (-not (Test-Path $imageDir)) {
            Write-Warning "skip   $name (system image not installed: $package)"
            continue
        }

        Write-Host "create $name ($package, device $Device)"
        # Answer "no" to the custom hardware profile prompt.
        'no' | & $avdmanager create avd --name $name --package $package --device $Device --tag $Tag --abi $Abi
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "failed $name (avdmanager exit $LASTEXITCODE)"
        }
    }
} finally {
    $env:JAVA_HOME        = $savedJavaHome
    $env:ANDROID_SDK_ROOT = $savedSdkRoot
}
