# Toolchain environment for android-threat-engine.
#
# Usage (from the project root, in each new PowerShell session):
#   . .\env.ps1
#
# Changes apply to the current session only. Nothing is written to the
# user or machine environment.
#
# JAVA_HOME points to JDK 8 for building the project. The SDK tools in
# cmdline-tools 23.0 need Java 17; run them with JDK 17 explicitly, e.g.:
#   $env:JAVA_HOME = $Jdk17Home; sdkmanager --list_installed; $env:JAVA_HOME = $Jdk8Home

$Jdk8Home  = 'C:\Android\jdk8'
$Jdk17Home = 'C:\Android\jdk17'
$SdkRoot   = 'C:\Android\Sdk'

foreach ($dir in @($Jdk8Home, $SdkRoot)) {
    if (-not (Test-Path $dir)) {
        Write-Warning "Missing toolchain directory: $dir"
    }
}

$env:JAVA_HOME        = $Jdk8Home
$env:ANDROID_HOME     = $SdkRoot
$env:ANDROID_SDK_ROOT = $SdkRoot

$prepend = @(
    (Join-Path $Jdk8Home 'bin'),
    (Join-Path $SdkRoot 'cmdline-tools\latest\bin'),
    (Join-Path $SdkRoot 'platform-tools'),
    (Join-Path $SdkRoot 'emulator')
)

# Drop any earlier copies so dot-sourcing twice does not grow PATH.
$rest = $env:Path -split ';' | Where-Object { $_ -and ($prepend -notcontains $_.TrimEnd('\')) }
$env:Path = ($prepend + $rest) -join ';'

Write-Host "JAVA_HOME=$env:JAVA_HOME"
Write-Host "ANDROID_HOME=$env:ANDROID_HOME"
