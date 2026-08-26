# COV real-injection KAT (auditor §1): force a REAL production dependency to fail and prove the affected class goes
# partial while the run still completes -- i.e. the collector's own catch routed to CovError. NOT a simulated CovError
# call and NOT a source-grep. Each case shadows a cmdlet with a throwing proxy (functions win over cmdlets in command
# resolution; Waldo does not redefine these three), then dot-sources the ACTUAL waldo.ps1 with -Only <class> and reads
# the emitted JSON coverage.
# Run:  pwsh -NoProfile -File waldo/tests/cov_inject_kat.ps1     (exit 0 = all PASS)  [Windows PowerShell/pwsh only]
$ErrorActionPreference = 'Stop'
$ps1 = Join-Path (Split-Path $PSScriptRoot -Parent) 'waldo.ps1'
$pass=0;$fail=0
$cases = @(
  @{ class='proc';       label='Get-Process';        why='process/listener enumeration'; proxy="function Get-Process { throw 'INJECTED_FAILURE' }" }
  @{ class='autostart';  label='Get-ScheduledTask';  why='scheduled-task collection';     proxy="function Get-ScheduledTask { throw 'INJECTED_FAILURE' }" }
  # The creds class intentionally has broad filesystem/registry sweeps in v2.20. It is covered by cov_kat source-wiring
  # assertions and focused logic KATs; real-injection here stays on bounded classes so it completes on a live workstation.
  # Collection-class injection is intentionally omitted here: the same dependencies are also used by later always-on
  # host-role inference, which can correctly attribute the injected error to `id` rather than `collection`.
)
foreach($c in $cases){
  $jf = Join-Path $env:TEMP ("waldo_inject_"+$c.class+"_"+([Math]::Abs($c.label.GetHashCode()))+".json")
  Remove-Item $jf -ErrorAction SilentlyContinue
  $pre = if ($c.forceElev) { "`$env:WALDO_TEST_FORCE_ELEVATED='1'; " } else { '' }
  $only = if ($c.only) { $c.only } else { $c.class }
  # bound the deep filesystem sweeps so every case completes predictably (a timeout does NOT satisfy the assertion --
  # it still requires an INJECTED_FAILURE record from the targeted production catch)
  $inner = "`$env:WALDO_DEADLINE='1'; ${pre}$($c.proxy); . '$ps1' -Only '$only' -Medium -NoContent -JsonOut '$jf' *> `$null"
  & (Get-Process -Id $PID).Path -NoProfile -Command $inner 2>$null | Out-Null
  if (-not (Test-Path $jf)) { $fail++; "FAIL  [$($c.class)/$($c.label)] no JSON produced"; continue }
  $j = Get-Content $jf -Raw | ConvertFrom-Json
  $completed = [bool]$j.scan_completed
  $state = [string]$j.coverage.$($c.class).state
  $named = @($j.collectors | Where-Object { $_.state -eq 'error' -and $_.reason -match 'INJECTED_FAILURE' }).Count -gt 0
  Remove-Item $jf -ErrorAction SilentlyContinue
  if ($completed -and $state -eq 'partial' -and $named) {
    $pass++; "PASS  [$($c.class)] inject $($c.label) throw -> class PARTIAL, run completed, error recorded ($($c.why))"
  } else {
    $fail++; "FAIL  [$($c.class)] inject $($c.label): completed=$completed state=$state named-error=$named ($($c.why))"
  }
}
"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
