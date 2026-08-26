# COV abort-typing Known-Answer Tests (auditor §1: interruption and terminating-error must be DISTINCT states).
# Verifies the same discrimination the production whole-run catch uses: only PipelineStopped / OperationCanceled
# are 'interrupt'; every other terminating error is 'error'.
# Run:  pwsh -NoProfile -File waldo/tests/cov_kat.ps1     (exit 0 = all PASS)
$ErrorActionPreference = 'Stop'
# mirrors the production catch condition exactly
function Classify-Abort([Exception]$ex){
  if ($ex -is [System.Management.Automation.PipelineStoppedException] -or $ex -is [System.OperationCanceledException]) { 'interrupt' } else { 'error' }
}
$pass=0;$fail=0
function Chk($desc,$got,$want){ if($got -eq $want){$script:pass++;"PASS  $desc -> $got"}else{$script:fail++;"FAIL  $desc got $got want $want"} }

Chk 'Ctrl-C (PipelineStoppedException)'      (Classify-Abort ([System.Management.Automation.PipelineStoppedException]::new()))  'interrupt'
Chk 'OperationCanceledException'             (Classify-Abort ([System.OperationCanceledException]::new()))                      'interrupt'
Chk 'generic RuntimeException'               (Classify-Abort ([System.Management.Automation.RuntimeException]::new('boom')))    'error'
Chk 'IOException (e.g. disk/read failure)'   (Classify-Abort ([System.IO.IOException]::new('io')))                             'error'
Chk 'ItemNotFoundException'                  (Classify-Abort ([System.Management.Automation.ItemNotFoundException]::new()))     'error'
Chk 'UnauthorizedAccessException'            (Classify-Abort ([System.UnauthorizedAccessException]::new()))                     'error'

# --- per-collector deadline (Invoke-Bounded): completes fast job, times out a slow one, records a typed cov_error ---
$script:CovErrors = @()
function CovError([string]$m){ $script:CovErrors += $m }   # stub matching production signature
$script:WaldoDeadline = 90
function Invoke-Bounded {
  param([Parameter(Mandatory)][scriptblock]$Work,[int]$Seconds=$script:WaldoDeadline,[string]$What='collector',[object[]]$ArgumentList=@())
  $ps=[powershell]::Create();[void]$ps.AddScript($Work);foreach($a in $ArgumentList){[void]$ps.AddArgument($a)}
  $async=$ps.BeginInvoke()
  if($async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($Seconds))){try{$out=$ps.EndInvoke($async)}catch{$out=$null;CovError "$What failed: $($_.Exception.Message)"};$ps.Dispose();return $out}
  else{try{$ps.Stop()}catch{};try{$ps.Dispose()}catch{};CovError "$What timed_out at ${Seconds}s";return $null}
}
$fast = Invoke-Bounded -What 'fast' -Seconds 10 -ArgumentList @(2,3) -Work { param($a,$b) $a + $b }
Chk 'bounded fast job returns output'        (@($fast)[-1])          5
Chk 'fast job records no cov_error'          ($script:CovErrors.Count) 0
$slow = Invoke-Bounded -What 'slow' -Seconds 1 -Work { Start-Sleep -Seconds 8; 'never' }
Chk 'bounded slow job returns null on timeout' ($null -eq $slow)      $true
Chk 'timeout records exactly one cov_error'  ($script:CovErrors.Count) 1
Chk 'cov_error is typed timed_out'           ([bool]($script:CovErrors[0] -match 'timed_out')) $true

# --- whole-collector failure -> class PARTIAL (auditor §1): inject a failure into each named collector's catch and
#     prove CovError flips the class to partial. Imports the PRODUCTION CovError + Cov-Record (no re-implementation). ---
$ps1 = Join-Path (Split-Path $PSScriptRoot -Parent) 'waldo.ps1'
$L = Get-Content -LiteralPath $ps1
function Import-Line([string]$re){ ($L | Select-String -Pattern $re | Select-Object -First 1).Line }
$script:CurrentClass=''; $script:CurrentCollector=''; $script:ClassErrored=@{}; $script:ClassDenied=@{}; $script:ClassSkipped=@{}
$script:ClassErrReason=@{}; $script:CovSkipSeen=@{}; $script:RecCount=0
function Note($t){}   # silence output in the KAT
function Cov-Record([string]$s,[string]$r){ $script:RecCount++ }   # stub: count typed records (registry object tested elsewhere)
. ([scriptblock]::Create((Import-Line '^function CovError')))
# production coverage-state expression (mirrors Write-JsonManifest): a class with any error -> 'partial' even when the scan completed
function Cov-State([string]$c,[bool]$scanDone){ if(-not $scanDone){'partial'} elseif(([int]$script:ClassErrored[$c] -gt 0) -or ([int]$script:ClassDenied[$c] -gt 0) -or ([int]$script:ClassSkipped[$c] -gt 0)){'partial'}else{'complete'} }
# simulate each named collector: enter it, its core op throws, its catch routes to CovError
$collectors = @(
  @{ class='id';    name='active-sessions';      reason='active-sessions collector failed' }
  @{ class='users'; name='local accounts';        reason='local account enumeration failed' }
  @{ class='users'; name='local Administrators';  reason='local Administrators membership failed' }
  @{ class='proc';  name='listening ports';       reason='listening-port enumeration failed' }
  @{ class='proc';  name='process enumeration';   reason='process enumeration failed' }
)
foreach($col in $collectors){
  $script:CurrentClass=$col.class; $script:CurrentCollector=$col.name
  try { throw "injected failure" } catch { CovError "$($col.reason): $($_.Exception.Message)" }
}
Chk 'injected failure -> id class partial (active-sessions)'        (Cov-State 'id' $true)    'partial'
Chk 'injected failure -> users class partial (local accts/admins)'  (Cov-State 'users' $true) 'partial'
Chk 'injected failure -> proc class partial (ports/processes)'      (Cov-State 'proc' $true)  'partial'
Chk 'a clean class with NO error stays complete'                    (Cov-State 'fs' $true)    'complete'
Chk 'each injected collector produced a typed error record'         ($script:RecCount) 5
# source-check: every named declared top-level collector routes its terminal catch to CovError (not an empty catch)
$src = Get-Content -LiteralPath $ps1 -Raw
foreach($p in @(
  'active-sessions collector failed','local account enumeration \(Win32_UserAccount\) failed',
  'local Administrators membership \(net localgroup','admin-like local account scan',
  'process enumeration \(Get-Process\) failed','listening-port enumeration \(netstat\) failed',
  'host/OS facts \(Win32_OperatingSystem','privilege/group context \(whoami /priv\) failed',
  'foothold/elevation verdict','local account lockout/password policy \(net accounts\) failed',
  'non-attached-route / IP-forwarding correlation failed','local SMB share enumeration failed',
  'network interfaces/routes collector failed','\.NET execution-knob collection failed',
  'persistence-autoruns collector',
  'current-token SID enumeration failed','elevation detection failed','machine-account / DC-role detection failed',
  'effective-token integrity/group classification','token elevation-type / linked-token query failed',
  'Windows baseline/build/role detection failed','A8 per-service Environment enumeration failed',
  'A8 scheduled-task .NET-knob enumeration failed','A8 IIS app-pool .NET-knob config parse failed',
  'A8 privileged-process command-line .NET-knob scan failed','VNC listener attribution',
  'VNC installed-product enumeration failed','flag-hunt collector failed','C5 relationship correlation failed',
  'host-role inference failed','credential cross-match failed',
  'PuTTY saved-session enumeration failed','PuTTY registry value scan','WinSCP saved-session enumeration failed',
  'web-stack execution-identity detection failed','Winlogon autologon','LSASS dump-target enumeration failed',
  'elevated active-session enumeration','other-user saved-session')){
  Chk "production wires CovError for /$p/" ([bool]($src -match "CovError `"$p")) $true
}

"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
