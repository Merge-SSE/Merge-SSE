<#
.SYNOPSIS
    Runs D1C search benchmarks on 10K/50K/100K/200K/400K-document datasets, in both the
    dense and sparse regimes, using the delta values from ../deltas.txt.

.DESCRIPTION
    For each dataset size and regime this invokes:
        .\D1C.exe -f ../input/inverted_index_<N>_<regime>.txt -u <N_updates> [-s] -d <delta> -p <page_size>

    Output for each run is logged to logs/D1C_<regime>_<N>.log (stdout+stderr) and a
    short pass/fail summary is printed at the end. D1C.exe itself writes its structured
    benchmark results to ../benchmarks/D1C-dense/ and ../benchmarks/D1C-sparse/.

.PARAMETER p
    Page size, passed through as D1C.exe's -p. Required, no default: it must match whatever
    page_size the dense/sparse input files were split with (see index_parser.py -p), otherwise
    usable_slots won't match how the data was partitioned and results will be meaningless.

.PARAMETER u
    Number of update queries, passed through as D1C.exe's -u (default: 1000).
#>

param(
    [Parameter(Mandatory = $true)]
    [int]$p,

    [int]$u = 1000
)

$ErrorActionPreference = "Stop"

# Run from the D1C/ directory regardless of where the script is invoked from,
# since D1C.exe resolves ../input and ../benchmarks relative to its own cwd.
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".\D1C.exe")) {
    Write-Error "D1C.exe not found in $PSScriptRoot. Build it first: g++ *.cpp -o D1C.exe -lcrypto -lssl"
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

$deltaDense = Get-DeltaTable -Section "D1C-dense" -Path $deltasFile
$deltaSparse = Get-DeltaTable -Section "D1C-sparse" -Path $deltasFile
if ($deltaDense.Count -eq 0 -or $deltaSparse.Count -eq 0) {
    Write-Error "Could not find 'D1C-dense'/'D1C-sparse' sections with entries in $deltasFile"
    exit 1
}
$sizes = $deltaDense.Keys | Sort-Object

$logDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$results = @()

foreach ($regime in @("dense", "sparse")) {
    $deltas = if ($regime -eq "dense") { $deltaDense } else { $deltaSparse }

    foreach ($n in $sizes) {
        $inputFile = "../input/inverted_index_${n}_${regime}.txt"
        if (-not (Test-Path $inputFile)) {
            Write-Warning "Skipping $regime / $n : input file not found ($inputFile)"
            $results += [pscustomobject]@{ Regime = $regime; N = $n; Delta = $deltas[$n]; Status = "MISSING INPUT" }
            continue
        }

        $delta = $deltas[$n]
        $logFile = Join-Path $logDir "D1C_${regime}_${n}.log"

        $argList = @("-f", $inputFile, "-u", $u, "-d", $delta, "-p", $p)
        if ($regime -eq "sparse") {
            $argList += "-s"
        }

        Write-Host "Running D1C: regime=$regime N=$n delta=$delta p=$p u=$u ..." -ForegroundColor Cyan
        $startTime = Get-Date

        # D1C.exe can print a non-fatal WARNING to stderr (e.g. high cuckoo-hash load factor);
        # under $ErrorActionPreference = "Stop" that gets escalated into a terminating
        # NativeCommandError by PowerShell's native-command handling, aborting the whole script
        # even though the run itself would succeed. Relax to "Continue" for just this call and
        # rely on $LASTEXITCODE (checked below) for the actual pass/fail signal.
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & ".\D1C.exe" @argList *> $logFile
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP

        $elapsed = (Get-Date) - $startTime
        $status = if ($exitCode -eq 0) { "OK" } else { "FAILED (exit $exitCode)" }

        Write-Host ("  -> {0} in {1:N1}s (log: {2})" -f $status, $elapsed.TotalSeconds, $logFile) -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })

        $results += [pscustomobject]@{
            Regime  = $regime
            N       = $n
            Delta   = $delta
            Status  = $status
            Seconds = [math]::Round($elapsed.TotalSeconds, 1)
            Log     = $logFile
        }
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Yellow
$results | Format-Table -AutoSize
