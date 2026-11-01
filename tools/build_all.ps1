<#
.SYNOPSIS
    Build every Ghera benchmark and record one result per benchmark per build flavor.

.DESCRIPTION
    Loops over every benchmark folder under benchmarks/ghera/<Category>/<Benchmark>
    (the Misc and TemplateCategory folders are not benchmarks and are skipped).
    Each benchmark holds several Gradle projects (Benign, Malicious, Secure,
    BenignPartner, Library/version1.x and so on). For each project the script:
      1. creates local.properties with sdk.dir=C:/Android/Sdk if it is missing;
      2. runs gradlew.bat assembleDebug with JAVA_HOME set to C:\Android\jdk8;
      3. checks which flavor outputs (APK or AAR) were written by this run.

    The Testing project of each benchmark holds instrumentation tests, not apps,
    and is skipped unless -IncludeTesting is given.

    Projects that apply Misc/sdkFlavors.gradle build the flavors api22 to api27
    and apiDIST. Projects without product flavors are recorded as flavor
    "default". A benchmark gets "success" for a flavor only when every project
    that builds that flavor exited with code 0 and wrote a fresh output for it.

    Rows are appended to data/build-results.csv with the columns
    benchmark, flavor, result, timestamp. The header is written when the file
    does not exist yet. Gradle logs go to data/build-logs/.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\build_all.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\build_all.ps1 -Filter 'ICC/*'
#>
[CmdletBinding()]
param(
    # Wildcard on "<Category>/<Benchmark>", for example 'ICC/*' or '*/SQLite-*'.
    [string]$Filter = '*',
    [switch]$IncludeTesting
)

$ErrorActionPreference = 'Stop'

$Root       = Split-Path -Parent $PSScriptRoot
$GheraRoot  = Join-Path $Root 'benchmarks\ghera'
$DataDir    = Join-Path $Root 'data'
$CsvPath    = Join-Path $DataDir 'build-results.csv'
$LogDir     = Join-Path $DataDir 'build-logs'
$SdkDir     = 'C:/Android/Sdk'
$Jdk8Home   = 'C:\Android\jdk8'
$SkipTop    = @('Misc', 'TemplateCategory')
$FlavorFile = Join-Path $GheraRoot 'Misc\sdkFlavors.gradle'

if (-not (Test-Path $GheraRoot)) { throw "Benchmarks not found: $GheraRoot" }
if (-not (Test-Path $Jdk8Home))  { throw "JDK 8 not found: $Jdk8Home" }
New-Item -ItemType Directory -Force -Path $DataDir, $LogDir | Out-Null

# Flavor names from Misc/sdkFlavors.gradle: "[22, 23, ...].each" gives apiNN, plus "apiDIST".
function Get-SdkFlavors {
    $text = Get-Content -Raw $FlavorFile
    $flavors = @()
    if ($text -match '\[([\d,\s]+)\]\.each') {
        $flavors += ($Matches[1] -split ',') | ForEach-Object { 'api' + $_.Trim() }
    }
    $flavors += [regex]::Matches($text, '"(api[A-Za-z]+)"\s*\{') | ForEach-Object { $_.Groups[1].Value }
    if (-not $flavors) { throw "No flavors found in $FlavorFile" }
    return $flavors
}
$SdkFlavors = Get-SdkFlavors

function Get-ExpectedFlavors([string]$ProjectDir) {
    $gradleFiles = Get-ChildItem -Path $ProjectDir -Recurse -Filter 'build.gradle' -File |
        Where-Object { $_.FullName -notmatch '\\build\\' }
    foreach ($f in $gradleFiles) {
        if (Select-String -Path $f.FullName -Pattern 'sdkFlavors\.gradle' -Quiet) { return $SdkFlavors }
    }
    return @('default')
}

# Flavors whose debug output (APK or AAR) was written at or after $Since.
function Get-BuiltFlavors([string]$ProjectDir, [datetime]$Since) {
    $built = @{}
    $outputs = Get-ChildItem -Path $ProjectDir -Recurse -File -Include '*.apk', '*.aar' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\build\\outputs\\' -and $_.LastWriteTime -ge $Since }
    foreach ($o in $outputs) {
        if ($o.Name -match '-(api[A-Za-z0-9]+)-debug(-unsigned)?\.(apk|aar)$') {
            $built[$Matches[1]] = $true
        } elseif ($o.Name -match '-debug(-unsigned)?\.(apk|aar)$') {
            $built['default'] = $true
        }
    }
    return $built
}

function Write-ResultRow([string]$Benchmark, [string]$Flavor, [string]$Result) {
    $row = [pscustomobject]@{
        benchmark = $Benchmark
        flavor    = $Flavor
        result    = $Result
        timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
    }
    if (Test-Path $CsvPath) {
        $row | Export-Csv -Path $CsvPath -Append -NoTypeInformation -Encoding UTF8
    } else {
        $row | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    }
}

$benchmarks = Get-ChildItem -Path $GheraRoot -Directory |
    Where-Object { $SkipTop -notcontains $_.Name } |
    ForEach-Object { Get-ChildItem -Path $_.FullName -Directory } |
    Where-Object { "$($_.Parent.Name)/$($_.Name)" -like $Filter } |
    Sort-Object { "$($_.Parent.Name)/$($_.Name)" }

$savedJavaHome = $env:JAVA_HOME
$env:JAVA_HOME = $Jdk8Home
try {
    foreach ($bench in $benchmarks) {
        $benchName = $bench.Name
        Write-Host "== $($bench.Parent.Name)/$benchName"

        $projects = Get-ChildItem -Path $bench.FullName -Recurse -Filter 'gradlew.bat' -File |
            Where-Object { $_.FullName -notmatch '\\(build|\.gradle)\\' } |
            ForEach-Object { $_.Directory } |
            Where-Object { $IncludeTesting -or ($_.Name -ne 'Testing') }

        if (-not $projects) {
            Write-Warning "No Gradle project in $benchName"
            Write-ResultRow $benchName 'default' 'failure'
            continue
        }

        # flavor -> $true while every project that builds it has succeeded
        $flavorOk = [ordered]@{}

        foreach ($proj in $projects) {
            $localProps = Join-Path $proj.FullName 'local.properties'
            if (-not (Test-Path $localProps)) {
                Set-Content -Path $localProps -Value "sdk.dir=$SdkDir" -Encoding ASCII
                Write-Host "   created $localProps"
            }

            $rel     = $proj.FullName.Substring($bench.FullName.Length).TrimStart('\')
            $logName = ($benchName + '_' + ($rel -replace '[\\/]', '_') + '.log')
            $logPath = Join-Path $LogDir $logName
            $start   = (Get-Date).AddSeconds(-2)

            Write-Host "   $rel : gradlew.bat assembleDebug"
            Push-Location $proj.FullName
            try {
                & cmd.exe /c "gradlew.bat assembleDebug > `"$logPath`" 2>&1"
                $exit = $LASTEXITCODE
            } finally {
                Pop-Location
            }

            $built = Get-BuiltFlavors $proj.FullName $start
            foreach ($flavor in (Get-ExpectedFlavors $proj.FullName)) {
                $ok = ($exit -eq 0) -and $built.ContainsKey($flavor)
                if ($flavorOk.Contains($flavor)) {
                    $flavorOk[$flavor] = $flavorOk[$flavor] -and $ok
                } else {
                    $flavorOk[$flavor] = $ok
                }
            }
            Write-Host "   $rel : exit $exit, log $logName"
        }

        foreach ($flavor in $flavorOk.Keys) {
            $result = if ($flavorOk[$flavor]) { 'success' } else { 'failure' }
            Write-ResultRow $benchName $flavor $result
            Write-Host "   $flavor : $result"
        }
    }
} finally {
    $env:JAVA_HOME = $savedJavaHome
}

Write-Host "Results appended to $CsvPath"
