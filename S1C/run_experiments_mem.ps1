<#
.SYNOPSIS
    Runs S1C's search benchmark in in-memory mode (-m) on the largest dataset (400K docs),
    for comparison against the on-disk results from run_experiments.ps1.

.DESCRIPTION
    Invokes:
        .\S1C.exe -f ../input/inverted_index_400000.txt -p <page_size> -d <delta> -m

    Only the largest dataset is run because ../benchmark_plots/plot_mem_search.py keeps a
    single result per scheme/regime (it does not select "largest" among duplicates), matching
    how the other plot_*.py scripts already only plot the largest instance.

    Output is logged to logs/S1C_mem_400000.log. S1C.exe itself writes its structured
    benchmark results to ../benchmarks/mem-results/ (kept separate from the on-disk results
    in ../benchmarks/S1C-all/ so the two don't overwrite each other).

.PARAMETER p
    Page size, passed through as S1C.exe's -p. Required, no default.
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
$n = 400000
if (-not $deltas.ContainsKey($n)) {
    Write-Error "No S1C delta for ${n} in $deltasFile"
    exit 1
}
$delta = $deltas[$n]

$inputFile = "../input/inverted_index_${n}.txt"
if (-not (Test-Path $inputFile)) {
    Write-Error "Input file not found: $inputFile"
    exit 1
}

$logDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir "S1C_mem_${n}.log"

Write-Host "Running S1C (in-memory): N=$n delta=$delta p=$p ..." -ForegroundColor Cyan
$startTime = Get-Date

# S1C.exe can print a non-fatal WARNING to stderr (e.g. high cuckoo-hash load factor);
# under $ErrorActionPreference = "Stop" that gets escalated into a terminating
# NativeCommandError by PowerShell's native-command handling, aborting the whole script
# even though the run itself would succeed. Relax to "Continue" for just this call and
# rely on $LASTEXITCODE (checked below) for the actual pass/fail signal.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& ".\S1C.exe" -f $inputFile -p $p -d $delta -m *> $logFile
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $prevEAP

$elapsed = (Get-Date) - $startTime
$status = if ($exitCode -eq 0) { "OK" } else { "FAILED (exit $exitCode)" }

Write-Host ("  -> {0} in {1:N1}s (log: {2})" -f $status, $elapsed.TotalSeconds, $logFile) -ForegroundColor $(if ($exitCode -eq 0) { "Green" } else { "Red" })
Write-Host "Result written to ../benchmarks/mem-results/"
