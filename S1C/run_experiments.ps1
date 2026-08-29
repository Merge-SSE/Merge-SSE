<#
.SYNOPSIS
    Runs S1C search benchmarks on 10K/50K/100K/200K/400K-document datasets, using the delta
    values from ../deltas.txt. Unlike D1C, S1C is static, so there is no dense/sparse split
    and no update-query phase.

.DESCRIPTION
    For each dataset size this invokes:
        .\S1C.exe -f ../input/inverted_index_<N>.txt -p <page_size> -d <delta>

    Output for each run is logged to logs/S1C_<N>.log (stdout+stderr) and a short
    pass/fail summary is printed at the end. S1C.exe itself writes its structured
    benchmark results to ../benchmarks/.

.PARAMETER p
    Page size, passed through as S1C.exe's -p. Required, no default: it should be the
    optimal page size found via find_page_size.ps1.
#>

param(
    [Parameter(Mandatory = $true)]
    [int]$p
)

$ErrorActionPreference = "Stop"

# Run from the S1C/ directory regardless of where the script is invoked from,
# since S1C.exe resolves ../input and ../benchmarks relative to its own cwd.
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".\S1C.exe")) {
    Write-Error "S1C.exe not found in $PSScriptRoot. Build it first: g++ *.cpp -o S1C.exe -lcrypto -lssl"
    exit 1
}

$deltasFile = Join-Path $PSScriptRoot "../deltas.txt"
if (-not (Test-Path $deltasFile)) {
    Write-Error "deltas.txt not found at $deltasFile"
    exit 1
}

# Parses a "<Section>\n- 10K: 0.9\n- 50K: 1.5\n...\n\n" block out of deltas.txt into
# a { size_in_docs -> delta } table, so this script stays correct if deltas.txt changes.
function Get-DeltaTable {
    param([string]$Section, [string]$Path)

    $table = @{}
    $inSection = $false
    foreach ($line in Get-Content $Path) {
        $trimmed = $line.Trim()
        if ($trimmed -eq $Section) {
            $inSection = $true
            continue
        }
        if (-not $inSection) { continue }
        if ($trimmed -eq "") { break }
        if ($trimmed -match '^-\s*(\d+)K\s*:\s*([\d.]+)\s*$') {
            $table[[int]$matches[1] * 1000] = [double]$matches[2]
        }
    }
    return $table
}

$deltas = Get-DeltaTable -Section "S1C" -Path $deltasFile
if ($deltas.Count -eq 0) {
    Write-Error "Could not find an 'S1C' section with entries in $deltasFile"
    exit 1
}

$logDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$results = @()

foreach ($n in ($deltas.Keys | Sort-Object)) {
    $inputFile = "../input/inverted_index_${n}.txt"
    if (-not (Test-Path $inputFile)) {
        Write-Warning "Skipping N=$n : input file not found ($inputFile)"
        $results += [pscustomobject]@{ N = $n; Delta = $deltas[$n]; Status = "MISSING INPUT" }
        continue
    }

    $delta = $deltas[$n]
    $logFile = Join-Path $logDir "S1C_${n}.log"

    Write-Host "Running S1C: N=$n delta=$delta p=$p ..." -ForegroundColor Cyan
    $startTime = Get-Date

    # S1C.exe can print a non-fatal WARNING to stderr (e.g. high cuckoo-hash load factor);
    # under $ErrorActionPreference = "Stop" that gets escalated into a terminating
    # NativeCommandError by PowerShell's native-command handling, aborting the whole script
    # even though the run itself would succeed. Relax to "Continue" for just this call and
    # rely on $LASTEXITCODE (checked below) for the actual pass/fail signal.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & ".\S1C.exe" -f $inputFile -p $p -d $delta *> $logFile
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevEAP

    $elapsed = (Get-Date) - $startTime
    $status = if ($exitCode -eq 0) { "OK" } else { "FAILED (exit $exitCode)" }

    Write-Host ("  -> {0} in {1:N1}s (log: {2})" -f $status, $elapsed.TotalSeconds, $logFile) -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })

    $results += [pscustomobject]@{
        N       = $n
        Delta   = $delta
        Status  = $status
        Seconds = [math]::Round($elapsed.TotalSeconds, 1)
        Log     = $logFile
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Yellow
$results | Format-Table -AutoSize
