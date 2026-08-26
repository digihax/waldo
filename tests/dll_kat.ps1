# A7 DLL-search-order evidence -- Known-Answer Tests for the stock/non-stock import classifier.
# Imports the PRODUCTION $script:StockDllRe straight out of waldo.ps1 (no copy) so the test cannot drift
# from what ships. Verifies: stock System32 imports are filtered OUT (negative), genuinely non-stock
# dependencies are RETAINED (the positive that gates a task/service DLL-planting lead).
# Run:  pwsh -NoProfile -File waldo/tests/dll_kat.ps1     (exit 0 = all PASS)
$ErrorActionPreference = 'Stop'
$ps1 = Join-Path (Split-Path $PSScriptRoot -Parent) 'waldo.ps1'
$line = Select-String -Path $ps1 -Pattern '^\$script:StockDllRe\s*=' | Select-Object -First 1
if (-not $line) { "FAIL  could not locate `$script:StockDllRe in waldo.ps1"; exit 1 }
Invoke-Expression $line.Line   # defines $script:StockDllRe exactly as production does
$re = $script:StockDllRe
function Is-Stock([string]$n){ $n -match $re }

$pass=0;$fail=0
# strip a trailing .dll the way the production evidence path does before matching
function Norm([string]$n){ ($n -replace '\.dll$','') }
# stock System32 imports -- MUST be filtered out (no false-positive DLL-planting lead)
$stock = @('kernel32.dll','ntdll.dll','KERNELBASE.dll','user32.dll','advapi32.dll','ole32.dll','ws2_32.dll',
           'bcrypt.dll','crypt32.dll','shell32.dll','api-ms-win-core-processthreads-l1-1-1.dll',
           'System.Data.dll','Microsoft.Data.SqlClient.dll','mscoree.dll','vcruntime140.dll','ucrtbase.dll')
foreach($n in $stock){ if(Is-Stock (Norm $n)){$pass++;"PASS  stock filtered: $n"}else{$fail++;"FAIL  stock NOT filtered (would false-positive): $n"} }
# genuinely non-stock dependencies -- MUST be retained (these gate the writable-path lead)
$custom = @('sqlite3.dll','libpq.dll','helperlib.dll','mydb.dll','vendorauth.dll','CustomPlugin.dll','libeay32.dll')
foreach($n in $custom){ if(-not (Is-Stock (Norm $n))){$pass++;"PASS  non-stock retained: $n"}else{$fail++;"FAIL  non-stock wrongly filtered (missed lead): $n"} }
"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
