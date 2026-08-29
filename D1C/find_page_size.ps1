<#
.SYNOPSIS
    Sweeps page sizes in D1C's full-page-only mode to help find the optimal page_size
    (see README.md, "Compile D1C and benchmark its full page performance").

.DESCRIPTION
    For each page size this invokes:
        .\D1C.exe -f <InputFile> --fp -p <page_size> [-d <delta>]

    Output for each run is logged to logs/D1C_optp_<page_size>.log. D1C.exe itself writes
    its structured benchmark results to ../benchmarks/D1C-opt-p/, which
    ../benchmark_plots/benchmark_page_size_D1C.py reads to plot throughput vs. page size.

.PARAMETER f
    Input multi-map file to benchmark full pages on (default: ../input/inverted_index_400000.txt,
    the largest raw dataset -- only full pages are used in this mode, so dense/sparse splitting
    is irrelevant here).

.PARAMETER d
    Oversampling factor delta, passed through as D1C.exe's -d. Optional: if omitted, D1C.exe
    uses its own compiled-in default (see Types.cpp).

.PARAMETER PageSizes
    List of page sizes (bytes) to sweep. Defaults to the values historically used in this repo.
#>

param(
    [string]$f = "../input/inverted_index_400000.txt",

    [Nullable[double]]$d = $null,

    [int[]]$PageSizes = @(256, 512, 1024, 2048, 4096, 8192)
)

$ErrorActionPreference = "Stop"

# Run from the D1C/ directory regardless of where the script is invoked from,
# since D1C.exe resolves ../input and ../benchmarks relative to its own cwd.
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".\D1C.exe")) {
    Write-Error "D1C.exe not found in $PSScriptRoot. Build it first: g++ *.cpp -o D1C.exe -lcrypto -lssl"
    exit 1
}

if (-not (Test-Path $f)) {
    Write-Error "Input file not found: $f"
    exit 1
}

$logDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$results = @()

foreach ($pageSize in $PageSizes) {
    $logFile = Join-Path $logDir "D1C_optp_${pageSize}.log"

    $argList = @("-f", $f, "--fp", "-p", $pageSize)
    if ($null -ne $d) {
        $argList += @("-d", $d)
    }

    Write-Host "Running D1C --fp: page_size=$pageSize $(if ($d) { "delta=$d" }) ..." -ForegroundColor Cyan
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
        PageSize = $pageSize
        Status   = $status
        Seconds  = [math]::Round($elapsed.TotalSeconds, 1)
        Log      = $logFile
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Yellow
$results | Format-Table -AutoSize
Write-Host "Results written to ../benchmarks/D1C-opt-p/ -- plot with ../benchmark_plots/benchmark_page_size_D1C.py"
