# B2 stable-evidence-ID dedup -- Known-Answer Tests. Imports the PRODUCTION Add-Lead / Get-LeadCategory /
# Redact-ForId functions straight out of waldo.ps1 (brace-matched extraction, no copy) and asserts the v0.34
# contract: leads dedup on the CANONICAL IDENTITY tuple, not the prose title.
# Run:  pwsh -NoProfile -File waldo/tests/b2_kat.ps1     (exit 0 = all PASS)
$ErrorActionPreference = 'Stop'
$ps1  = Join-Path (Split-Path $PSScriptRoot -Parent) 'waldo.ps1'
$lines = Get-Content -LiteralPath $ps1

# extract a `function <name> { ... }` block by brace-matching from its declaration line
function Import-Fn([string]$name){
  $start = ($lines | Select-String -Pattern "^function\s+$([regex]::Escape($name))\b" | Select-Object -First 1).LineNumber
  if (-not $start) { throw "function $name not found" }
  $depth = 0; $buf = @()
  for ($i = $start - 1; $i -lt $lines.Count; $i++){
    $ln = $lines[$i]; $buf += $ln
    $depth += ([regex]::Matches($ln,'\{')).Count - ([regex]::Matches($ln,'\}')).Count
    if ($i -ge $start -and $depth -le 0) { break }
  }
  return ($buf -join "`n")
}
# minimal script-scope state the functions touch
$script:LeadKeys = @{}; $script:Leads = New-Object System.Collections.ArrayList; $script:CurrentClass = 'services'
. ([scriptblock]::Create((Import-Fn 'Redact-ForId')))
. ([scriptblock]::Create((Import-Fn 'Get-LeadCategory')))
. ([scriptblock]::Create((Import-Fn 'Add-Lead')))

$pass=0;$fail=0
function Chk($desc,$got,$want){ if($got -eq $want){$script:pass++;"PASS  $desc (=$got)"}else{$script:fail++;"FAIL  $desc got $got want $want"} }

# 1) SAME title, DIFFERENT canonical source -> two distinct leads (must NOT collapse)
$script:LeadKeys=@{}; $script:Leads.Clear()
Add-Lead 90 "Writable service target: svcA -> C:\a\a.exe" "why" -CanonicalSource 'C:\a\a.exe' -Consumer 'svcA' -Primitive 'privesc-write'
Add-Lead 90 "Writable service target: svcA -> C:\a\a.exe" "why" -CanonicalSource 'C:\b\b.exe' -Consumer 'svcB' -Primitive 'privesc-write'
Chk 'distinct evidence, same title -> 2 leads (no title-collapse)' $script:Leads.Count 2

# 2) DIFFERENT title, SAME canonical identity -> one lead (reworded duplicate collapses)
$script:LeadKeys=@{}; $script:Leads.Clear()
Add-Lead 70 "Writable service target: svcA -> C:\a\a.exe" "why" -CanonicalSource 'C:\a\a.exe' -Consumer 'svcA' -Primitive 'privesc-write'
Add-Lead 95 "Service binary you can overwrite (svcA)" "why" -CanonicalSource 'C:\a\a.exe' -Consumer 'svcA' -Primitive 'privesc-write'
Chk 'same identity, reworded title -> 1 lead (collapsed)' $script:Leads.Count 1
Chk 'collapse keeps the HIGHER score' $script:Leads[0].Score 95

# 3) secret in the canonical source is redacted before it can key the ID
$script:LeadKeys=@{}; $script:Leads.Clear()
Add-Lead 60 "Inline cred: password=Secret123 in web.config" "why"
Chk 'secret redacted out of CanonicalSource' ([bool]($script:Leads[0].CanonicalSource -match '(?i)Secret123')) $false

# 4) B2 long-tail: two NO-COLON titles sharing an embedded path -> same canonical source (category fixed to isolate
#    the source-extraction: rewording the prose around the path must not change the derived source/ID).
$script:LeadKeys=@{}; $script:Leads.Clear()
Add-Lead 70 "Writable autostart target C:\ProgramData\app\run.exe found" "why" -Category 'privesc-write'
Add-Lead 90 "You can overwrite C:\ProgramData\app\run.exe at logon" "why" -Category 'privesc-write'
Chk 'no-colon titles sharing an embedded path (same category) -> 1 lead (stable source across prose)' $script:Leads.Count 1
Chk 'embedded path became the canonical source' ([bool]($script:Leads[0].CanonicalSource -match 'run\.exe')) $true

# 5) Windows path WITH SPACES captured whole (auditor §3: the old regex truncated at the first space -> collisions)
$script:LeadKeys=@{}; $script:Leads.Clear()
Add-Lead 70 "Writable service binary C:\Program Files\Vendor App\svc.exe found" "why" -Category 'privesc-write'
Chk 'Windows path with spaces captured whole (not truncated)' ([bool]($script:Leads[0].CanonicalSource -match 'Vendor App\\svc\.exe')) $true
$script:LeadKeys=@{}; $script:Leads.Clear()
Add-Lead 70 "Writable binary C:\Program Files\A\x.exe" "w" -Category 'privesc-write'
Add-Lead 70 "Writable binary C:\Program Files\B\y.exe" "w" -Category 'privesc-write'
Chk 'distinct spaced paths sharing a prefix do NOT collide' $script:Leads.Count 2

# 6) title-only scored lead with EXPLICIT typed facts: rewording the prose keeps an identical ID (network-topology class)
$script:LeadKeys=@{}; $script:Leads.Clear()
Add-Lead 95 "Dual-homed host (2 segments: 10.10/16, 192.168/24)" "why" -CanonicalSource 'dual-homed' -Consumer 'network-topology' -Primitive 'pivot-multihomed'
Add-Lead 95 "Host bridges two networks -- pivot candidate" "why" -CanonicalSource 'dual-homed' -Consumer 'network-topology' -Primitive 'pivot-multihomed'
Chk 'reworded title-only lead w/ explicit facts -> identical ID (1 lead)' $script:Leads.Count 1

# 7) STRICT COVERAGE ASSERTION (auditor §2): statically parse waldo.ps1 and FAIL unless EVERY scored Add-Lead supplies
#    all three explicit identity params -CanonicalSource, -Consumer, -Primitive. No title-heuristic whitelist -- the
#    contract is now enforced at the call boundary, not derived from prose.
$tokens=$null;$perr=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($ps1,[ref]$tokens,[ref]$perr)
$calls=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Lead'},$true)
$missing=@()
foreach($c in $calls){
  $names=@($c.CommandElements | Where-Object {$_ -is [System.Management.Automation.Language.CommandParameterAst]} | ForEach-Object {$_.ParameterName})
  if(-not (($names -contains 'CanonicalSource') -and ($names -contains 'Consumer') -and ($names -contains 'Primitive'))){
    $missing += "L$($c.Extent.StartLineNumber): $((($c.CommandElements[2].Extent.Text) -replace '\s+',' '))"
  }
}
if($missing.Count -eq 0){ $pass++; "PASS  B2 STRICT coverage: all $($calls.Count) scored Add-Lead sites supply explicit CanonicalSource+Consumer+Primitive" }
else { $fail++; "FAIL  B2 STRICT coverage: $($missing.Count)/$($calls.Count) Add-Lead sites missing an explicit identity param:"; $missing | Select-Object -First 15 | ForEach-Object { "        $_" } }

"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
