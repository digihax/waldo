# A8 .NET execution-knob coverage -- Known-Answer Tests for the extraction + consumer-correlation logic.
# Mirrors the production sources (task action, IIS applicationHost.config app-pool, running command line) and the
# privileged-vs-nonprivileged consumer decision. Uses synthetic inputs so no real task/IIS/process is required.
# Run:  pwsh -NoProfile -File waldo/tests/a8_kat.ps1     (exit 0 = all PASS)
$ErrorActionPreference = 'Stop'
$KnobRe  = '(?i)(DOTNET_STARTUP_HOOKS|COR_PROFILER|COR_ENABLE_PROFILING|COR_PROFILER_PATH)\s*=\s*([^\s&|"]+)'
function Extract-Knob([string]$s){ if ($s -match $KnobRe) { @{ name=$Matches[1]; val=$Matches[2] } } else { $null } }
function Is-PrivConsumer([string]$u){ [bool]($u -match '(?i)system|administrator') }
$pass=0;$fail=0
function Chk($d,$g,$w){ if($g -eq $w){$script:pass++;"PASS  $d -> $g"}else{$script:fail++;"FAIL  $d got [$g] want [$w]"} }

# 1) SYSTEM scheduled-task action sets COR_PROFILER inline -> positive, privileged
$taskCl = 'cmd /c set COR_PROFILER={11111111-1111-1111-1111-111111111111} && C:\svc\app.exe'
$k = Extract-Knob $taskCl
Chk 'task action: knob extracted (name)'  ($k.name)  'COR_PROFILER'
Chk 'task action: knob extracted (value)' ($k.val)   '{11111111-1111-1111-1111-111111111111}'
Chk 'task run-as SYSTEM -> privileged consumer' (Is-PrivConsumer 'NT AUTHORITY\SYSTEM') $true

# 2) IIS applicationHost.config app-pool environmentVariables -> positive, privileged (app-pool)
$ahc = @'
<configuration><system.applicationHost><applicationPools>
  <add name="AppPoolA"><environmentVariables>
    <add name="DOTNET_STARTUP_HOOKS" value="C:\hooks\h.dll" />
  </environmentVariables></add>
  <add name="StockPool"><environmentVariables/></add>
</applicationPools></system.applicationHost></configuration>
'@
[xml]$x = $ahc
$hits = @()
foreach($ap in @($x.configuration.'system.applicationHost'.applicationPools.add)){
  foreach($ev in @($ap.environmentVariables.add)){
    if ($ev.name -match '(?i)^(DOTNET_STARTUP_HOOKS|COR_PROFILER|COR_ENABLE_PROFILING|COR_PROFILER_PATH)$') { $hits += "$($ap.name):$($ev.name)=$($ev.value)" }
  }
}
Chk 'IIS app-pool: exactly one knob hit'   ($hits.Count) 1
Chk 'IIS app-pool: names the pool + knob'  ($hits[0])    'AppPoolA:DOTNET_STARTUP_HOOKS=C:\hooks\h.dll'

# 3) running command line (service consumer) with a knob -> positive
$svcCl = 'C:\svc\worker.exe --config x  COR_ENABLE_PROFILING=1'
Chk 'service command line: knob detected' ([bool](Extract-Knob $svcCl)) $true

# 4) nonprivileged consumer -> NOT privileged (lower impact, still reported by the collector)
Chk 'normal user consumer -> not privileged' (Is-PrivConsumer 'CORP\alice') $false

# 5) negative: a stock app pool / command line with no knob -> no hit
Chk 'no-knob command line -> no extraction' ([bool](Extract-Knob 'C:\app\clean.exe --port 8080')) $false

"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
