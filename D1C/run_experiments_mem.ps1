<#
.SYNOPSIS
    Runs D1C's search benchmark in in-memory mode (-m) on the largest dataset (400K docs),
    in both the dense and sparse regimes, for comparison against the on-disk results from
    run_experiments.ps1.

.DESCRIPTION
    For each regime this invokes:
        .\D1C.exe -f ../input/inverted_index_400000_<regime>.txt -u <n_updates> [-s] -d <delta> -p <page_size> -m

    Only the largest dataset is run because ../benchmark_plots/plot_mem_search.py keeps a
    single result per scheme/regime (it does not select "largest" among duplicates), matching
    how the other plot_*.py scripts already only plot the largest instance.

    Output is logged to logs/D1C_mem_<regime>_400000.log. D1C.exe itself writes its structured
    benchmark results to ../benchmarks/mem-results/ (kept separate from the on-disk results in
    ../benchmarks/D1C-dense/ and ../benchmarks/D1C-sparse/ so the two don't overwrite each other).

.PARAMETER p
    Page size, passed through as D1C.exe's -p. Required, no default: it must match whatever
    page_size the dense/sparse input files were split with (see index_parser.py -p).

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

$n = 400000
$logDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

foreach ($regime in @("dense", "sparse")) {
    $deltas = Get-DeltaTable -Section "D1C-$regime" -Path $deltasFile
    if (-not $deltas.ContainsKey($n)) {
        Write-Error "No D1C-$regime delta for $n in $deltasFile"
        exit 1
    }
    $delta = $deltas[$n]

    $inputFile = "../input/inverted_index_${n}_${regime}.txt"
    if (-not (Test-Path $inputFile)) {
        Write-Warning "Skipping $regime : input file not found ($inputFile)"
        continue
    }

    $logFile = Join-Path $logDir "D1C_mem_${regime}_${n}.log"

    $argList = @("-f", $inputFile, "-u", $u, "-d", $delta, "-p", $p, "-m")
    if ($regime -eq "sparse") {
        $argList += "-s"
    }

    Write-Host "Running D1C (in-memory): regime=$regime N=$n delta=$delta p=$p u=$u ..." -ForegroundColor Cyan
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
}

Write-Host "Results written to ../benchmarks/mem-results/"
