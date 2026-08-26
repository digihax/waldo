<#
  waldo.ps1  --  "Where's Waldo?"  Windows enumeration by ANOMALY (ENUMERATION ONLY).

  v2.12 adds: active sessions, persistence autoruns
  (AppInit/IFEO/WMI-subs/LSA), listener owner/path enrichment, local SMB shares + sharing configs,
  SPN listing, benign account flags, SYSVOL GPP cpassword (report-only, never decrypted),
  service-ACL detail, host-role inference, cred cross-match. All observe-and-advise; no new actions.
  v2.13 adds -Root <path>: triage a MOUNTED target filesystem (shared-out C:\) re-rooted -- readable
  hives (RegBack/Windows.old) -> offline secretsdump, flags, per-user creds, writable drop-targets.
  v2.14 adds full group/member roster (not just priv groups) + source-aware lockout/password policy
  ([LOCAL] net accounts vs [DOMAIN] LDAP threshold/observation-window) -- know it BEFORE you spray.
  v2.15: per-object try/catch in the AD walk (one bad SD no longer aborts it); machine-account/
  SYSTEM-on-DC labeling; post-admin credential-source checklist (+Credential Guard state); credential SCOPE
  (local/domain/DA/machine) + per-artifact scope tags; local app-DB as first-class lead (read on-box first);
  Administrator.<HOST> flag highlight; objective-aware nudge (local.txt w/o proof -> local privesc here);
  server-product config/version/service-account breadcrumbs; writable-GPO note; operator-artifact bucket.

  Philosophy: WinPEAS is ADDITIVE (shows everything it knows to check).
  Waldo is SUBTRACTIVE: it knows what a STANDARD box looks like and shows you
  only what does NOT belong -- the folder, user, service, port, autorun, or
  script that stands out. Then it PEEKS INSIDE anomalous files for secrets.

  v2 adds CORRELATION: high-value findings are scored into a "Top Waldo Leads"
  summary at the end, so the classic signature --
      non-standard C:\Scripts  +  writable backup.exe  +  SYSTEM task runs it
  -- surfaces as ONE ranked, actionable lead instead of three scattered lines.

  READ-ONLY enumeration: makes no target changes and sends no exploit/attack traffic; writes only to a
  chosen -OutFile/-JsonOut path. Default enumeration may make one read-only LDAP query on a domain-joined
  host (allowed enumeration). Built-in cmdlets only (with WMI fallbacks for legacy 2008/2012 boxes).

  Flag legend:
    [!]  yellow  -> non-standard  (Waldo spotted)
    [!!] red     -> non-standard AND writable/modifiable by you (possible privesc condition)
    [x]  gray    -> access denied (noted -- gaps are interesting too)
    [i]  cyan    -> context/info
    [*]  magenta -> section header

  Usage:
    powershell -ep bypass -f waldo.ps1          # DEFAULT = full + deep (everything -- first run, best run)
    . .\waldo.ps1                       # dot-source / paste into a shell
    waldo.ps1 -Medium                   # all classes, skip the heavy sweeps (faster)
    waldo.ps1 -Light                    # quick high-signal triage (no deep, no log-mining)
    waldo.ps1 -Only creds,flags         # run only some check classes (-List to see them)
    waldo.ps1 -Skip logs                # run everything except a class
    waldo.ps1 -Loot C:\loot             # offline triage of already-pulled files (no target interaction)
    waldo.ps1 -Root Z:\                  # triage a MOUNTED target root (shared-out C:\): net use Z: \\host\C$ first

    waldo.ps1 -AD                       # read-only AD outbound-rights LDAP check (auto-on if domain-joined)
    waldo.ps1 -AD -ADUser corp\user -ADPass <password>  # run the AD check AS a supplied domain user (see THEIR edges)
    waldo.ps1 -LowPriv                  # force writable checks even if elevated
    waldo.ps1 -OutFile C:\Temp\waldo.txt
    waldo.ps1 -NoContent                # skip grepping file contents
    waldo.ps1 -NoColor

  Check classes (-Only/-Skip): id users fs services autostart proc privesc creds logs flags collection ad

  Pair it with WinPEAS: Waldo to SPOT the anomaly fast, WinPEAS to deep-dive it.
#>

[CmdletBinding()]
param(
  [switch]$Deep,
  [string]$OutFile,
  [switch]$NoContent,
  [switch]$NoColor,
  [switch]$LowPriv,            # force low-priv writable checks even if the scan is elevated
  [switch]$ShowOperatorLeads,  # let operator-dropped tool artifacts rank normally (default: capped)
  [string]$Only,               # run only these check classes (comma-separated)
  [string]$Skip,               # run all but these check classes
  [switch]$Full,               # explicit "everything" (== the default: all classes + deep)
  [switch]$Medium,             # all classes, skip the heavy sweeps
  [switch]$Light,              # quick high-signal triage (no deep, no log-mining)
  [switch]$List,               # list check classes and exit
  [string]$Loot,               # offline triage of an already-pulled loot directory
  [string]$Root,               # point at a MOUNTED target filesystem root (e.g. a shared-out C:\ via net use Z: \\host\C$)
  [switch]$AD,                 # force the read-only AD outbound-rights LDAP check (auto-on if domain-joined)
  [string]$ADUser,             # run the AD check AS this principal (dom\user) -- see THEIR edges (e.g. a cracked app user)
  [string]$ADPass,             # password for -ADUser
  [switch]$DecodeLocalSecrets, # A5b: opt-in offline decode of documented reversible local secrets (VNC). OFF by default.
  [string]$JsonOut             # v2.17 B2: write a machine-readable manifest (leads/coverage/artifacts) to FILE
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# Check classes -- run subsets with -Only / -Skip (default/-Full = everything).
$script:Classes = 'id','users','fs','services','autostart','proc','privesc','creds','logs','flags','collection','ad'
$script:WaldoVersion = '2.20'; $script:SchemaVersion = '1'; $script:BuildDate = '2026-08-23'; $script:FlagState = 'NOT_CHECKED'; $script:FlagSearchEvidence = @(); $script:FlagSuperseded = $false; $script:DeniedFlagPath = $null
$script:CurrentClass = ''; $script:CurrentCollector = ''; $script:ClassDenied = @{}; $script:ClassSkipped = @{}; $script:ClassErrored = @{}; $script:ClassErrReason = @{}; $script:CovSkipSeen = @{}   # v0.15/v0.27/v0.31 COV: per-class + per-COLLECTOR outcomes
$script:Collectors = New-Object System.Collections.ArrayList; $script:CovRecSeen = @{}   # COV registry: one typed record per {class, collector, state}
# v0.42 A5: structured VNC state model -- independent typed fields per artifact + signature coverage, emitted to JSON
# (not just concatenated in a lead's prose). Populated by the VNC collector; empty when the class is skipped.
$script:VncFindings = New-Object System.Collections.ArrayList; $script:VncSignature = $null; $script:VncRole = 'unknown'; $script:VncActivity = 'unknown'
function Cov-Record([string]$state,[string]$reason){ $k = "$($script:CurrentClass)|$($script:CurrentCollector)|$state"; if($script:CovRecSeen[$k]){ return }; $script:CovRecSeen[$k]=$true; [void]$script:Collectors.Add([pscustomobject]@{ class=$script:CurrentClass; collector=$(if($script:CurrentCollector){$script:CurrentCollector}else{'(class-level)'}); state=$state; reason=$reason }) }
# v0.41 COV: per-collector wall-clock deadline (mirrors the Linux run_bounded/timeout guarantee). Env-overridable.
$script:WaldoDeadline = if ($env:WALDO_DEADLINE -match '^\d+$' -and [int]$env:WALDO_DEADLINE -gt 0) { [int]$env:WALDO_DEADLINE } else { 90 }
# Invoke-Bounded { <read-only collection> } -Seconds N -What '<label>': run a data-collection scriptblock in a CHILD
# runspace with a hard time cap. Returns its output on completion; on timeout it stops the runspace and records a typed
# cov_error(timed_out) so the class is honestly PARTIAL, not silently complete. The scriptblock is a separate runspace,
# so it must be self-contained (pass inputs via -ArgumentList; use only built-in cmdlets; no $script: mutation inside).
function Invoke-Bounded {
  param([Parameter(Mandatory)][scriptblock]$Work, [int]$Seconds = $script:WaldoDeadline, [string]$What = 'collector', [object[]]$ArgumentList = @())
  $ps = [powershell]::Create()
  [void]$ps.AddScript($Work)
  foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
  $async = $ps.BeginInvoke()
  if ($async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($Seconds))) {
    try { $out = $ps.EndInvoke($async) } catch { $out = $null; CovError "$What failed: $($_.Exception.Message)" }
    $ps.Dispose(); return $out
  } else {
    try { $ps.Stop() } catch {}; try { $ps.Dispose() } catch {}
    CovError "$What timed_out at ${Seconds}s -- enumeration INCOMPLETE (raise WALDO_DEADLINE or run that check manually)"
    return $null
  }
}
if ($List) { Write-Host ("check classes: " + ($script:Classes -join ' ')); exit 0 }
# DEFAULT = full+deep (everything). Dial down with -Medium / -Light.
$script:DeepMode = $true
if ($Medium -or $Light) { $script:DeepMode = $false }
if ($Deep -or $Full) { $script:DeepMode = $true }
$script:OnlySet = @(); if ($Only) { $script:OnlySet = ($Only -split '[, ]+' | Where-Object { $_ }) }
$script:SkipSet = @(); if ($Skip) { $script:SkipSet = ($Skip -split '[, ]+' | Where-Object { $_ }) }
if ($Light) { $script:SkipSet += 'logs' }   # light = quick triage: no log-mining
# ROOT MODE: triage a MOUNTED target filesystem root. Reuse loot's host-enum-skip by aliasing $Loot,
# but branch to Invoke-RootTriage (structured, re-rooted) instead of the generic loot recurse.
$script:RootMode = $false
if ($Root) {
  $Root = $Root.TrimEnd('\'); if (-not $Root) { $Root = (Get-Item -LiteralPath (Split-Path -Qualifier $PWD)).FullName }
  if (-not (Test-Path -LiteralPath $Root)) { Write-Host "root path not found: $Root" -ForegroundColor Red; exit 1 }
  $script:RootMode = $true; $Loot = $Root
}
function Want([string]$Class){
  if ($Loot) { return $false }                                # loot mode: skip target-side host enum
  if ($script:Classes -notcontains $Class) { $script:CurrentClass = $Class; return $true }
  if ($script:OnlySet.Count -gt 0 -and $script:OnlySet -notcontains $Class) { return $false }
  if ($script:SkipSet -contains $Class) { return $false }
  $script:CurrentClass = $Class; return $true
}

# Flagged-binary registry: discovery sections record basenames; history/log mining cross-references
# them so a known anomaly's USAGE (with ANY args) is surfaced unfiltered. Discovery runs before
# history; a final reconciliation pass catches binaries flagged after their usage line was read.
$script:FlaggedBins = @{}
$script:DbCredHint = @()   # configs where a DB-shaped credential was seen
$script:DbListener = @()   # local DB listener ports observed
$script:OperatorArtifacts = @{}   # likely operator-created files -> shown in their own bucket, not just suppressed
function Add-FlaggedBin([string]$PathOrName){
  if (-not $PathOrName) { return }
  $b = try { [IO.Path]::GetFileName($PathOrName.Trim('"')) } catch { $PathOrName }
  if ($b) { $script:FlaggedBins[$b.ToLower()] = $true }
}
function Test-FlaggedBin([string]$Name){ if (-not $Name) { return $false }; return $script:FlaggedBins.ContainsKey($Name.ToLower()) }
$script:HistBuf = New-Object System.Collections.ArrayList   # buffered @{Src;Line} for reconciliation
# positional-arg secret heuristic: local exe/script followed by a high-entropy token (>=8, mixed alnum)
function Test-PositionalToken([string]$Line){
  $m = [regex]::Match($Line,'(?i)([.\\/]?[\w.-]+\.(exe|ps1|bat|cmd|vbs|py|jar))\s+(\S{8,})')
  if (-not $m.Success) { return $false }
  $tok = $m.Groups[3].Value
  if ($tok -match '^[-/]' -or $tok -match '^\d+(\.\d+)*$' -or $tok -match '(?i)^(password|username|localhost)$') { return $false }
  return ($tok -match '[A-Za-z]' -and $tok -match '\d')
}
# Read a history file: print capped content, flag (a) any line invoking an already-flagged binary
# (UNFILTERED, all args) and (b) local-tool + positional-token creds; buffer lines for reconciliation.
function Analyze-History([string]$Path,[string]$User){
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $lines = @(); try { $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop) } catch { return }
  if (-not $lines) { return }
  Sub "history: $Path ($User)"
  if (-not $NoContent) { $lines | Select-Object -Last 60 | ForEach-Object { if ($_){ $s=[string]$_; Note ("  " + $s.Substring(0,[Math]::Min(180,$s.Length))) } } }
  Add-CredArtifact 'shell/PS history (readable -- review for reused creds/commands)' $Path
  foreach($ln in $lines){
    $ln = [string]$ln
    if (-not $ln) { continue }
    [void]$script:HistBuf.Add(@{ Src=$Path; Line=$ln })
    $hit = $null
    foreach($tok in ($ln -split '\s+')){ $tb = try { [IO.Path]::GetFileName($tok.Trim('"')) } catch { $tok }; if (Test-FlaggedBin $tb) { $hit=$tb; break } }
    if ($hit) {
      Jackpot ("history runs flagged tool '$hit': " + $ln.Substring(0,[Math]::Min(200,$ln.Length)))
      Add-Lead 90 "History runs flagged tool '$hit'" "$ln  ::  a previously-flagged custom binary is invoked -- ANY argument (incl. a positional password) is high-signal. Manual review." -CanonicalSource (Redact-ForId "$hit") -Consumer 'history-runs-flagged-tool' -Primitive 'history-runs-flagged-tool'
      Add-CredArtifact '[history-credential] flagged-tool usage' "$Path : $ln"
    } elseif (Test-PositionalToken $ln) {
      Jackpot ("history: local tool + high-entropy positional arg: " + $ln.Substring(0,[Math]::Min(200,$ln.Length)))
      Add-Lead 82 "Positional credential in history: $Path" "$ln  ::  a local exe/script invoked with a password-shaped positional token. Manual review." -CanonicalSource (Redact-ForId "$Path") -Consumer 'positional-credential-in-history' -Primitive 'positional-credential-in-history'
      Add-CredArtifact '[history-credential] positional token' "$Path : $ln"
    }
  }
}

# =====================================================================
#  BASELINES  --  what "standard" looks like. EDIT THESE per box/OS.
# =====================================================================

$Std_CUsers = @(
  'Default','Default User','Public','All Users','Administrator',
  'defaultuser0','WDAGUtilityAccount','desktop.ini'
)

$Std_RootC = @(
  'Windows','Program Files','Program Files (x86)','Users','ProgramData',
  'PerfLogs','Recovery','$Recycle.Bin','System Volume Information',
  'Documents and Settings','$WinREAgent','$SysReset','OneDriveTemp',
  'pagefile.sys','hiberfil.sys','swapfile.sys','bootmgr','BOOTNXT',
  'DumpStack.log.tmp','DumpStack.log','desktop.ini','autoexec.bat','config.sys'
)

$Std_ProgramFiles = @(
  'Common Files','Internet Explorer','Windows Defender',
  'Windows Defender Advanced Threat Protection','Windows Mail',
  'Windows Media Player','Windows Multimedia Platform','Windows NT',
  'Windows Photo Viewer','Windows Portable Devices','Windows Security',
  'WindowsApps','WindowsPowerShell','Microsoft','Microsoft.NET',
  'ModifiableWindowsApps','Reference Assemblies','Uninstall Information',
  'Windows Sidebar','MSBuild','dotnet','desktop.ini'
)
$Std_ProgramFilesX86 = $Std_ProgramFiles + @(
  'Microsoft.NET','Microsoft SQL Server','Microsoft Visual Studio',
  'MSBuild','Windows Kits','Windows Defender','Common Files'
)

# ProgramData top-level subdirs that are stock (the rest get zone-scanned).
$Std_ProgramData = @(
  'Microsoft','Packages','Package Cache','Microsoft OneDrive','regid.1991-06.com.microsoft',
  'SoftwareDistribution','USOShared','USOPrivate','ssh','Windows','WindowsHolographicDevices',
  'Comms','GameBar','Intel','NVIDIA','NVIDIA Corporation','Application Data','Documents',
  'Start Menu','Templates','Desktop','MicrosoftEdgeUpdate','ntuser.pol','desktop.ini'
)

# First-class "app/data root" zones worth a deep look when present.
$AppRoots = @(
  'C:\ProgramData','C:\inetpub','C:\Tools','C:\Scripts','C:\Backup','C:\Backups',
  'C:\Apps','C:\App','C:\wwwroot','C:\web','C:\www','C:\xampp','C:\wamp','C:\wamp64',
  'C:\laragon','C:\transfer','C:\temp','C:\Temp','C:\tmp','C:\Data','C:\opt','C:\install','C:\shares',
  'C:\bd'
)

$Std_Ports = @(135,137,138,139,445,500,3389,5985,5986,49664,49665,49666,49667,49668,49669,49670)
$Std_SchedPrefix = @('\Microsoft\','\Windows\')

$InterestingExt = @(
  '.ps1','.bat','.cmd','.vbs','.js','.wsf','.config','.ini','.xml','.txt',
  '.log','.kdbx','.key','.pem','.ppk','.rdp','.yml','.yaml','.json','.env',
  '.sql','.bak','.old','.conf','.cfg','.psd1','.psm1','.reg','.php','.inc','.inf',
  # certs/keystores, saved sessions/VPN, DBs, crackable archives, web source, notes
  '.pfx','.p12','.jks','.keystore','.gpg','.vnc','.ovpn','.rdg',
  '.db','.sqlite','.sqlite3','.mdf','.properties','.toml','.csv','.md',
  '.aspx','.asp','.jsp','.cshtml','.htpasswd',
  '.zip','.7z','.rar','.tar','.gz','.tgz','.xlsx','.docx','.pdf',
  # password managers / credential vaults (beyond KeePass .kdbx)
  '.kdb','.psafe3','.opvault','.agilekeychain','.walletx','.kwallet'
)
# Files that are executable OPPORTUNITIES to surface (not grep) when in odd/writable paths.
$ExecExt = @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.wsf','.jar','.msi','.py')

# Secret grep. Assignment arm allows quotes/=> so it catches web-config idioms
# ($password='x', 'password'=>'x', define('DB_PASSWORD','x')) not just key:=value.
$SecretRegex = '(?i)((pass(word)?|pwd|secret|passwd|cred(ential)?s?|api[_-]?key|access[_-]?key|secret[_-]?key|token|connection ?string|user(name|id)?|login|db_pass|validationKey|decryptionKey|machineKey|auth[_-]?info|reg_identity|realm|registrar|sip_domain)[^A-Za-z0-9]{0,2}(=>|[:=])\s*\S+|<(pass(word)?|passwd|user(name)?|secret|token|auth([_-]?info)?|realm|registrar|proxy|api[_-]?key|sip_domain|reg_identity)[^>]*>[^<]+<|define\([^)]*(pass|pwd|secret|key|token)[^)]*,\s*\S+|(?-i)-----BEGIN (RSA|OPENSSH|EC|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY|ConvertTo-SecureString|-AsPlainText|net user \S+ \S+|cmdkey\s+/|:[0-9a-fA-F]{32}:)'

# v0.15 A7: stock/system DLLs resolve from System32 / KnownDLLs / GAC and are NOT hijackable via an app-dir plant.
# Filtering them leaves the app-specific imports that actually matter for a DLL-search-order condition.
$script:StockDllRe = '(?i)^(kernel32|kernelbase|ntdll|user32|win32u|gdi32|gdi32full|gdiplus|advapi32|msvcrt|ucrtbase|vcruntime\d*|msvcp\d*|msvcr\d*|concrt\d*|ole32|oleaut32|combase|shell32|shlwapi|shcore|ws2_32|wsock32|mswsock|rpcrt4|sechost|bcrypt|bcryptprimitives|ncrypt|crypt32|cryptbase|cryptsp|wldap32|winhttp|wininet|urlmon|iphlpapi|dnsapi|secur32|sspicli|schannel|netapi32|netutils|srvcli|version|imm32|comctl32|comdlg32|setupapi|cfgmgr32|devobj|powrprof|profapi|dbghelp|dbgcore|psapi|userenv|wtsapi32|msasn1|mpr|propsys|clbcatq|uxtheme|dwmapi|d3d\d+.*|dxgi|d2d1|dwrite|windows\.storage|wintypes|kernel\.appcore|msctf|textinputframework|coreuicomponents|coremessaging|ntmarta|mscoree|mscoreei|clr|clrjit|coreclr|hostpolicy|hostfxr|system\..*|microsoft\..*|api-ms-win.*|ext-ms-.*)$'
# v0.34 A9: a config file is cred-bearing (not an empty/stock template) when its text matches this. Drives the
# empty-template negative in Report-ConfigPath. Hoisted so tests import the exact production contract (no drift).
$script:CfgSecretRe = '(?i)(connectionstring|"?password"?\s*[:=]|\bpwd\s*=|user id\s*=|initial catalog|data source\s*=|\bsecret\b|accesskey|api[_-]?key|"?token"?\s*[:=]\s*"[^"]{6,})'
# v0.34 A7: reusable NON-stock DLL-import evidence for a binary -- used by the service, scheduled-task, and Run-key
# DLL-search-order gates (same concrete-dependency + writable-resolved-location rule everywhere, not just services).
function Get-NonStockDllEvidence([string]$exe){
  $dllNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase); $srcNote = @()
  if (-not $exe -or -not (Test-Path -LiteralPath $exe)) { return @{ Dlls=@(); Source=@() } }
  try { $fs=[System.IO.File]::OpenRead($exe); $cap=[int][Math]::Min($fs.Length,1MB); $buf=New-Object byte[] $cap; $rd=$fs.Read($buf,0,$cap); $fs.Close(); $ascii=[Text.Encoding]::ASCII.GetString($buf,0,$rd); foreach($m in [regex]::Matches($ascii,'(?<![\\/:.])([A-Za-z0-9_.-]+)\.dll')){ [void]$dllNames.Add($m.Groups[1].Value) }; if ($dllNames.Count) { $srcNote += 'binary imports' } } catch {}
  foreach($cf in @("$exe.config","$exe.manifest")){ if (-not (Test-Path -LiteralPath $cf)) { continue }; $ct = try { Get-Content -LiteralPath $cf -Raw -ErrorAction Stop } catch { '' }; $before=$dllNames.Count; foreach($rx in @('(?i)<file\b[^>]*\bname="([^"]+?)(\.dll)?"','(?i)<assemblyIdentity\b[^>]*\bname="([^"]+?)"','(?i)\bcodeBase\b[^>]*\bhref="([^"]+?)(\.dll)?"')){ foreach($m in [regex]::Matches($ct,$rx)){ $nm=($m.Groups[1].Value -replace '(?i)\.dll$',''); if($nm){ [void]$dllNames.Add($nm) } } }; if ($dllNames.Count -gt $before) { $srcNote += "sidecar $([IO.Path]::GetFileName($cf))" } }
  return @{ Dlls=@($dllNames | Where-Object { $_ -and $_ -notmatch $script:StockDllRe } | Sort-Object -Unique | Select-Object -First 6); Source=$srcNote }
}
$MaxPeekBytes = 400KB
$MaxPeekLines = 6
$ZoneFileCap  = 60      # max interesting files reported per scanned zone

# =====================================================================
#  OUTPUT / COLOR PLUMBING
# =====================================================================
$script:UseColor = -not $NoColor
# WinRM-safe output -- tee each line to $OutFile ourselves (Start-Transcript over WinRM
# gives locked/zero-byte files). Per-line append flushes as we go, so a dropped session leaves a partial file.
$script:OutFile = $OutFile; $script:LastSection = '(start)'
if ($OutFile) { try { Set-Content -LiteralPath $OutFile -Value ("# Waldo output " + $env:COMPUTERNAME) -ErrorAction Stop } catch { $script:OutFile = $null } }
function Say([string]$Text,[string]$Color='Gray'){
  if ($script:UseColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
  if ($script:OutFile) { try { Add-Content -LiteralPath $script:OutFile -Value $Text -ErrorAction SilentlyContinue } catch {} }
}
function Head($t){ $script:LastSection = $t; $script:CurrentCollector = '(class-level)'; Say ""; Say ("[*] === $t ===") 'Magenta' }
function Sub($t){  $script:CurrentCollector = $t; Say ("    -- $t") 'DarkCyan' }   # each sub-section IS a collector (COV registry attribution)
function Waldo($t){   Say ("  [!]  $t")  'Yellow' }
function Jackpot($t){ Say ("  [!!] $t")  'Red' }
function Denied($t){  Say ("  [x]  $t")  'DarkGray'; if($script:CurrentClass){ $script:ClassDenied[$script:CurrentClass] = 1 + ([int]$script:ClassDenied[$script:CurrentClass]) }; Cov-Record denied $t }
# CovSkip: a sub-collector could not run (missing tool / unavailable prerequisite) -> the class is PARTIAL, not complete. Deduped per class+reason.
function CovSkip([string]$reason){ $k = "$($script:CurrentClass):$reason"; if($script:CovSkipSeen[$k]){ return }; $script:CovSkipSeen[$k]=1; if($script:CurrentClass){ $script:ClassSkipped[$script:CurrentClass] = 1 + ([int]$script:ClassSkipped[$script:CurrentClass]) }; Cov-Record skipped $reason; Note ("  [~] sub-check skipped: $reason -- coverage for '$($script:CurrentClass)' is PARTIAL, not complete") }
# v0.27 COV: a collector that ERRORED / TIMED OUT declares it as an ERROR (tracked SEPARATELY from a tool-absent skip),
# with the reason retained for the footer AND JSON -- a silent catch/truncation no longer lets the class read 'complete'.
function CovError([string]$reason){ $k = "$($script:CurrentClass):E:$reason"; if($script:CovSkipSeen[$k]){ return }; $script:CovSkipSeen[$k]=1; if($script:CurrentClass){ $script:ClassErrored[$script:CurrentClass] = 1 + ([int]$script:ClassErrored[$script:CurrentClass]); if(-not $script:ClassErrReason[$script:CurrentClass]){ $script:ClassErrReason[$script:CurrentClass] = $reason } }; Cov-Record error $reason; Note ("  [~] collector error/timeout: $reason -- coverage for '$($script:CurrentClass)' is PARTIAL, not complete") }
function Info($t){    Say ("  [i]  $t")  'Cyan' }
function Note($t){    Say ("       $t")  'DarkGray' }

# =====================================================================
#  LEAD ENGINE  --  correlated, scored, ranked at the end.
# =====================================================================
$script:Leads = New-Object System.Collections.ArrayList
$script:LeadKeys = @{}; $script:ProseLeads = @()   # B2: WALDO_TRACK_PROSE dumps scored leads that fell back to prose-only identity
# v0.15 B1 fix: Get-LeadCategory MUST be defined BEFORE Add-Lead runs -- Add-Lead derives scope from it, and
# PowerShell only exposes a function after its definition executes. (Was previously defined at the bottom.)
function Get-LeadCategory([string]$t){
  switch -Regex ($t) {
    '(?i)flag|objective'                                    { 'flag'; break }
    '(?i)secret|credential|\bVNC\b|password|cred store'     { 'credential'; break }
    '(?i)SeImpersonate|token|GTFO|privilege|SUID'           { 'privesc-primitive'; break }
    '(?i)route|dual-homed|pivot|segment'                    { 'network-pivot'; break }
    '(?i)writable|service|autorun|DLL|startup|AppInit|IFEO' { 'privesc-write'; break }
    default { 'misc' }
  }
}
function Add-Lead([int]$Score,[string]$Title,[string]$Why,[string]$Finding='',[string]$Validate='',[string]$Scope='',[string]$Category='',[string]$CanonicalSource='',[string]$Consumer='',[string]$Primitive=''){
  # v0.24 B1: category is a STORED field, supplied by the collector when known else derived ONCE here (never re-derived at render).
  if (-not $Category) { $Category = Get-LeadCategory $Title }
  # v0.32 B2: canonical NON-SECRET facts the ID derives from (not the prose). Collectors MAY supply; else derive:
  #  source = the locator after the last ': ' (path/key/id), redacted; consumer = class; primitive = category.
  # v0.44 B2: stable non-secret source -- explicit locator after the last ': '; else an embedded path / quoted name
  # (so rewording a no-colon title's prose doesn't change the ID); else the whole title. High-signal leads pass facts.
  if (-not $CanonicalSource) {
    # Windows path branch allows SPACES within a path and anchors on the file extension (so "C:\Program Files\a\x.exe"
    # is captured whole, not truncated at the first space -> distinct spaced paths no longer collide).
    # v0.48 §2: a real Windows path (spaces ok, anchored on extension), OR a quoted token, OR a real UNIX absolute path
    # (>=2 segments, space/start-anchored -- NOT a lone slash in prose like "creds/flag"), else the whole title.
    $src = if ($Title -match ':\s(.+)$') { $Matches[1] }
           elseif ($Title -match "['""]([^'""]+)['""]") { $Matches[1] }
           elseif ($Title -match '([A-Za-z]:\\[^\r\n:*?"<>|]*?\.\w{1,6}|[A-Za-z]:\\[^\s]+)') { $Matches[1].TrimEnd() }
           elseif ($Title -match '(?:^|\s)(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+)') { $Matches[1] }
           else { if ($env:WALDO_TRACK_PROSE) { [void]($script:ProseLeads += "[$Score] $Title") }; $Title }
    $CanonicalSource = Redact-ForId $src
  }
  if (-not $Consumer)  { $Consumer  = if ($script:CurrentClass) { $script:CurrentClass } else { 'host' } }
  if (-not $Primitive) { $Primitive = $Category }
  # v0.34 B2: dedup on the CANONICAL IDENTITY tuple (the same facts the manifest ID hashes), NOT the prose title.
  # -> distinct evidence that happens to share a title does NOT collapse; the same evidence reworded DOES collapse.
  $k = "$Category|$CanonicalSource|$Consumer|$Primitive"
  if ($script:LeadKeys.ContainsKey($k)) {
    if ($Score -gt $script:LeadKeys[$k].Score) { $script:LeadKeys[$k].Score = $Score }
    return
  }
  # collectors MAY supply a distinct raw finding / bounded validate step / explicit scope; else derive from the stored category
  if (-not $Finding)  { $Finding = $Title }
  if (-not $Validate) { $Validate = 'confirm manually before acting; Waldo took no action' }
  if (-not $Scope)    { $Scope = switch ($Category) { 'flag' {'host-objective'} 'credential' {'credential-material'} 'network-pivot' {'segment'} default { if($Category -like 'privesc*'){'host-local'}else{'host'} } } }
  $o = [pscustomobject]@{ Score=$Score; Category=$Category; Title=$Title; Finding=$Finding; Why=$Why; Validate=$Validate; Scope=$Scope; CanonicalSource=$CanonicalSource; Consumer=$Consumer; Primitive=$Primitive }
  $script:LeadKeys[$k] = $o
  [void]$script:Leads.Add($o)
}
# v0.24 B2: strip secret-shaped content from a string BEFORE it is used to derive a stable ID (IDs must never be secret-derived).
function Redact-ForId([string]$s){
  if (-not $s) { return '' }
  # value after a known short-secret LABEL (community string, passcode, otp, ...) -- so 'public' never reaches the hash
  $s = $s -replace '(?i)(pass(word)?|pwd|secret|token|api[_-]?key|community|passcode|otp|credential)[^:=]{0,24}[:=]\s*\S+', '$1 <redacted>'
  $s = $s -replace '[A-Fa-f0-9]{16,}', '<hex>'
  $s = $s -replace '[A-Za-z0-9+/]{24,}={0,2}', '<b64>'
  return $s
}

# Credential-artifact rollup -- a clean handoff list (NO spraying/testing performed).
$script:CredArtifacts = New-Object System.Collections.ArrayList
$script:CredKeys = @{}
$script:CredNamedSeen = @{}   # A6 dedup: credential-named files already surfaced by the format-independent basename rule
# v0.15 A4: local privilege PRIMITIVES from ANY source (token privilege, writable service/binary, unquoted path,
# writable PATH dir) so C5's denied-objective->primitive relationship cites a SPECIFIC primitive, not just a token priv.
$script:PrivPrimitives = New-Object System.Collections.ArrayList
$script:PrimKeys = @{}
function Add-Primitive([string]$class,[string]$label){ $k="$class|$label"; if($script:PrimKeys[$k]){return}; $script:PrimKeys[$k]=1; [void]$script:PrivPrimitives.Add([pscustomobject]@{ Class=$class; Label=$label }) }
# v0.15 A11: strict default scope for a credential artifact (no cross-product, no validation advice).
function Cred-Scope([string]$t){ switch -Regex ($t) {
  '(?i)machine.?account|computer.?account|\bHOST\$|\bNT AUTHORITY\\SYSTEM\b|\$@'  { 'machine-account (non-interactive; authenticates as the COMPUTER on the network, not a user logon)'; break }
  '(?i)NTDS|DCSync|domain admin|\bDA\b'                                     { 'domain-principal (exact; subject to logon restrictions)'; break }
  '(?i)SAM|hive|LSA|shadow|local admin|\blocal\b'                          { 'origin-host-only'; break }
  '(?i)browser|chrome|firefox|edge|login.?data|vault|keepass|kdbx|Credential Manager|DPAPI|\.rdp\b|saved.?session|PuTTY|WinSCP|FileZilla' { 'origin-service-only (bound to the EXACT stored host/service; not portable elsewhere)'; break }
  '(?i)\bDB\b|SQL|postgres|mysql|mssql|app DB'                             { 'origin-service-only'; break }
  '(?i)SNMP|SIP|proxy|API|token|VNC'                                       { 'origin-service-only'; break }
  '(?i)provision|cloudbase|unattend'                                       { 'origin-host-only (until image-reuse evidence)'; break }
  default { 'unknown (do not test until corroborated)' }
} }
# v0.24 A11: retain the ACTUAL principal/secret pair when Waldo extracted one (not just a type+location wrapper);
# confidence reflects what was captured -- 'captured-pair' (both), 'principal-observed' (principal only), 'located' (pointer only).
function Add-CredArtifact([string]$Type,[string]$Where,[string]$Principal='',[string]$Secret=''){
  # A11: dedup on the FULL pair (type|where|principal|secret) so two DISTINCT principal/secret pairs from the same
  # source are BOTH kept (a Type|Where-only key would collapse them into one).
  $k = "$Type|$Where|$Principal|$Secret"
  if ($script:CredKeys.ContainsKey($k)) { return }
  $script:CredKeys[$k] = $true
  $conf = if ($Secret -and $Principal) { 'captured-pair' } elseif ($Secret) { 'secret-observed' } elseif ($Principal) { 'principal-observed' } else { 'located' }
  [void]$script:CredArtifacts.Add([pscustomobject]@{ Type=$Type; Where=$Where; Principal=$Principal; Secret=$Secret; Scope=(Cred-Scope $Type); Confidence=$conf; Tested=$false })
}
# v0.15 A8: scan a COMMAND LINE / task action / service binPath string for an INLINE credential (conservative patterns
# only, placeholders filtered) so secrets embedded in execution config -- not just env/registry -- are surfaced.
$script:InlineCredSeen = @{}
function Scan-InlineCred([string]$text,[string]$src){
  if (-not $text) { return }
  $pats = @(
    '(?i)(password|passwd|--pass|/pass|pwd)\s*[:= ]\s*["'']?([^\s"'';,]{4,})',   # password=... / -Password ...
    '(?i)(api[_-]?key|client[_-]?secret|secret|token|access[_-]?key)\s*[:= ]\s*["'']?([A-Za-z0-9+/_.\-]{8,})',
    '(?i)(Password|Pwd)\s*=\s*[^;\s"'']{4,}',                                      # connection-string Password=...
    '(?-i:(/RP|/P|-P))\s+["'']?(?=[^\s"'';,]*[A-Za-z])([^\s"'';,]{5,})'            # schtasks /RP, sqlcmd/osql -P/-P -- value must contain a letter (not a port)
  )
  foreach($p in $pats){
    $m = [regex]::Match($text,$p)
    if (-not $m.Success) { continue }
    $val = $m.Value.Trim()
    if ($val -match '(\*{2,}|%\w+%|\$\(|\$\{|\$env:|<[^>]*>|xxxx|changeme|placeholder|example|\byour[_-]?)' ) { continue }  # skip obvious placeholders
    if ($script:InlineCredSeen[$val]) { return }; $script:InlineCredSeen[$val] = 1
    Jackpot "inline credential in $src : $val"
    Add-Lead 84 "Inline credential in $src" "An execution-config value exposes an inline secret ($src): '$val'. Preserve the EXACT principal/secret pair with this origin; do NOT recombine across sources. Manual review -- Waldo does not test it." -CanonicalSource (Redact-ForId $src) -Consumer 'execution-config' -Primitive 'inline-credential'
    # A11: retain the captured secret token + any principal in the same match (user=/uid=/User Id=)
    $prin = ''; $pm = [regex]::Match($text,'(?i)(user(\s*id)?|uid|username)\s*[:=]\s*[''"]?([^\s''";,]+)'); if ($pm.Success) { $prin = $pm.Groups[3].Value }
    Add-CredArtifact "inline credential ($src)" $src $prin $val
    return
  }
}
# Label a secret sample by hash/cred type so the handoff says HOW to use it.
function Classify-Secret([string]$sample){
  if ($sample -match '\$DCC2\$|\$MACHINE\.ACC') { return 'DCC2 (crack-only)' }
  if ($sample -match '\$krb5tgs\$')             { return 'Kerberoast TGS (crack-only)' }
  if ($sample -match '\$krb5asrep\$')           { return 'AS-REP (crack-only)' }
  if ($sample -match '\$2[aby]\$')              { return 'bcrypt (crack-only)' }
  if ($sample -match '\$(6|5|1)\$')             { return 'unix crypt (crack-only)' }
  if ($sample -match '[a-fA-F0-9]{32}:[a-fA-F0-9]{32}|:[a-fA-F0-9]{32}:::') { return 'NTLM (pass-the-hash OR crack)' }
  return 'possible cleartext (scope=unknown, tested=false -- do not reuse until corroborated)'
}

# Operator artifact = a tool WE dropped during exploitation. Cap its rank so it doesn't
# outrank original lab anomalies (e.g. /tmp/waldo.sh, C:\Temp\PrintSpoofer.exe, rootbash).
$OperatorRe = '(?i)(waldo|waldo[_-].*\.(txt|log)|lin(peas|enum)|winpeas|peass?|chisel|ligolo|socat|ncat|netcat|RunasCs|PrintSpoofer|GodPotato|JuicyPotato|SweetPotato|rootbash|rootshell|proofshell|jdwp_relay|revshell|reverse|payload|meterpreter|mimikatz|rubeus|certipy|sharphound|secretsdump|procdump|nanodump|dump[_-]?hives|\bgp\.(exe|bat)|nc\.exe)'
function Is-Operator([string]$Path){
  if ($Loot) { return $false }   # loot files are pulled from a target, not tools we dropped here
  if ($Path -notmatch '(?i)(\\Temp\\|\\Windows\\Temp\\|\\Users\\[^\\]+\\(Downloads|Desktop)\\|^[A-Z]:\\Temp\\)') { return $false }
  if ($Path -match $OperatorRe) { $script:OperatorArtifacts[$Path] = $true; return $true }
  return $false
}
# Context-aware score for a secret hit -- a commented C:\Windows sample must not outrank a real custom-root secret.
function Score-SecretHit([string]$Path,[string]$Sample){
  if (Is-Operator $Path) { return @{ Score=40; Tag='[operator] ' } }
  if ($Sample -match '(?i)(=>|[:=])\s*["'']?(changeme|change_me|password|passwd|secret|example|foo|bar|test|xxx+|placeholder|yourpassword)["'']?\s*$') { return @{ Score=45; Tag='[placeholder] ' } }
  $noncomment = ($Sample -split "`n" | Where-Object { $_ -and ($_ -replace '^L?\d+:?\s*','') -notmatch '^\s*(#|;|//|\*|/\*|<!--)' }).Count
  if ($Path -match '(?i)^[A-Z]:\\Windows\\|\\Program Files\\.*\\(samples?|examples?|templates?)\\') {
    if ($noncomment -eq 0) { return @{ Score=45; Tag='[commented-example] ' } } else { return @{ Score=58; Tag='[stock-config] ' } }
  }
  if ($Path -match '(?i)\\(inetpub|wwwroot|www|xampp|wamp|laragon|Tools|Scripts|Backup|transfer|Apps)\\') { return @{ Score=85; Tag='[custom-root] ' } }
  if ($Path -match '(?i)\\(wp-config\.php|configuration\.php|database\.php|web\.config|\.env|unattend\.xml)$|\.(kdbx|ppk|pem|ovpn)$') { return @{ Score=80; Tag='' } }
  if ([IO.Path]::GetFileNameWithoutExtension($Path) -match '(?i)^(credentials?|creds|passwords?|secrets?|logins?|accounts?)$') { return @{ Score=86; Tag='[credential-named] ' } }
  return @{ Score=70; Tag='' }
}

# Cross-section correlation -- one app/vendor spanning many signal classes = the real target.
$script:AppSignals = @{}
function Norm-App([string]$s){
  if (-not $s) { return '' }
  $n = try { [IO.Path]::GetFileNameWithoutExtension($s) } catch { $s }
  ($n -replace '(?i)[\s_\-]?v?\d+([._]\d+)*$','' -replace '[^A-Za-z0-9]','').ToLower()
}
function Add-AppSignal([string]$Name,[string]$Tag){
  $k = Norm-App $Name
  if ($k.Length -lt 3) { return }
  if (-not $script:AppSignals.ContainsKey($k)) { $script:AppSignals[$k] = @{} }
  $script:AppSignals[$k][$Tag] = $true
}

# =====================================================================
#  HELPERS
# =====================================================================
$script:HasDepth = $false
try { $script:HasDepth = (Get-Command Get-ChildItem).Parameters.ContainsKey('Depth') } catch {}

function Get-Cim([string]$Class,[string]$Filter){
  try {
    if ($Filter) { Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction Stop }
    else         { Get-CimInstance -ClassName $Class -ErrorAction Stop }
  } catch {
    if ($Filter) { Get-WmiObject -Class $Class -Filter $Filter -ErrorAction SilentlyContinue }
    else         { Get-WmiObject -Class $Class -ErrorAction SilentlyContinue }
  }
}

function Is-Standard([string]$Name,[string[]]$Baseline){
  foreach($b in $Baseline){ if ($Name -ieq $b){ return $true } }
  return $false
}

# ===================================================================================================
#  v0.29 whole-run finalizer + try/finally. Defined BEFORE the scan so the finally can always reach it.
# ===================================================================================================
function Write-JsonManifest {
  if (-not $JsonOut) { return }
  $hash = try { if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) { (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash } else { $null } } catch { $null }
  $mguid = try { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid } catch { $null }
  $cov = [ordered]@{}; foreach($c in $script:Classes){ $_dc=[int]$script:ClassDenied[$c]; $_sk=[int]$script:ClassSkipped[$c]; $_er=[int]$script:ClassErrored[$c]; $_rsn=[string]$script:ClassErrReason[$c]; $_st = if ($Loot) { 'skipped' } elseif (Want $c) { if(-not $script:ScanCompleted){'partial'} elseif($_dc -gt 0 -or $_sk -gt 0 -or $_er -gt 0){'partial'}else{'complete'} } else { 'skipped' }; if($_st -eq 'partial' -and -not $_rsn -and -not $script:ScanCompleted){ $_rsn = if($script:AbortKind -eq 'interrupt'){'run interrupted (Ctrl-C) before this class completed'}elseif($script:AbortKind -eq 'error'){"run ended on a terminating error before this class completed: $script:AbortError"}else{'run ended before completion'} }; $cov[$c] = [ordered]@{ state=$_st; denied=$(if($_st -eq 'skipped'){0}else{$_dc}); skipped=$(if($_st -eq 'skipped'){0}else{$_sk}); errors=$(if($_st -eq 'skipped'){0}else{$_er}); error_reason=$(if($_st -eq 'skipped'){''}else{$_rsn}) } }
  $md5 = [System.Security.Cryptography.MD5]::Create()
  $machineId = if ($mguid) { $mguid } else { $env:COMPUTERNAME }
  $leads = @($script:Leads | Sort-Object Score -Descending | ForEach-Object {
    $cat = $_.Category
    # B2: ID derives from stable machine-id + category + CANONICAL non-secret facts (source|consumer|primitive), NOT the prose title
    $idhex = ([BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes("$machineId|$cat|$($_.CanonicalSource)|$($_.Consumer)|$($_.Primitive)"))) -replace '-','').Substring(0,12)
    [ordered]@{ id="$($env:COMPUTERNAME)-$cat-$idhex"; score=$_.Score; category=$cat; canonical_source=$_.CanonicalSource; consumer=$_.Consumer; primitive=$_.Primitive; title=$_.Title; finding=$_.Finding; why=$_.Why; validate=$_.Validate; scope=$_.Scope }
  })
  $m = [ordered]@{
    waldo_version=$script:WaldoVersion; schema_version=$script:SchemaVersion; build_date=$script:BuildDate
    script_sha256=$hash; source_mode=$(if($PSCommandPath){'file'}else{'stdin'})
    os='windows'; host_id=$(if($mguid){$mguid}else{$env:COMPUTERNAME}); hostname=$env:COMPUTERNAME; user=$env:USERNAME
    integrity=$script:IntegrityLevel; token_verdict=$script:TokenVerdict; elevated=[bool]$script:Elevated; admin_member=[bool]$script:AdminMember; latfp=$script:LATFP
    mode=$(if($Loot){'loot'}else{'host'}); interrupted=[bool]$script:Interrupted; abort_kind=$(if($script:AbortKind){$script:AbortKind}else{'none'}); abort_error=$script:AbortError; scan_completed=[bool]$script:ScanCompleted; flag_state=$script:FlagState; flag_superseded_after_reset=[bool]$script:FlagSuperseded; flag_search_evidence=@($script:FlagSearchEvidence | ForEach-Object { [ordered]@{ root=$_.root; status=$_.status } })
    baseline_family=$script:BaselineFamily; baseline_profile=$script:BaselineProfile; baseline_confidence=$script:BaselineConfidence
    coverage=$cov; collectors=@($script:Collectors | ForEach-Object { [ordered]@{ class=$_.class; collector=$_.collector; state=$_.state; reason=$_.reason } }); credential_artifacts=@($script:CredArtifacts | ForEach-Object { [ordered]@{ principal=$_.Principal; secret_captured=[bool]$_.Secret; type=$_.Type; origin=$_.Where; scope=$_.Scope; confidence=$_.Confidence; tested=$false } })
    vnc=[ordered]@{ role=$script:VncRole; activity=$script:VncActivity; signature_coverage=$(if($script:VncSignature){$script:VncSignature}else{[ordered]@{checked=0;present=0;not_found=0;denied=0}}); findings=@($script:VncFindings | ForEach-Object { [ordered]@{ origin=$_.origin; role=$_.role; activity=$_.activity; stale_possible=[bool]$_.stale_possible; auth_mode=$_.auth_mode; artifact_state=$_.artifact_state; format=$_.format; decode_state=$_.decode_state } }) }
    leads=$leads
  }
  try { $m | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $JsonOut -Encoding utf8; Info "JSON manifest -> $JsonOut" } catch { Note "JSON manifest write failed: $($_.Exception.Message)" }
}
$script:FooterDone = $false; $script:ScanCompleted = $false; $script:Interrupted = $false
# v0.40 COV: interruption and terminating-error are DISTINCT typed states (auditor §1). AbortKind is null on a clean
# run, 'interrupt' only for a real Ctrl-C (PipelineStopped/OperationCanceled), 'error' for any other terminating error.
$script:AbortKind = $null; $script:AbortError = ''
function Emit-Footer {
  if ($script:FooterDone) { return }; $script:FooterDone = $true
  try {
    Head "TOP WALDO LEADS -- look here first"
    if ($script:Leads.Count -eq 0) {
      Info "No high-confidence privesc leads correlated. Work the [!]/[!!] lines above,"
      Info "and run WinPEAS for the checks Waldo doesn't cover."
    } else {
      $ranked = $script:Leads | Sort-Object Score -Descending
      $hsN = @($ranked | Where-Object { $_.Title -match '(?i)^(\[doc secret\]|Flag file:|Credential store|Secrets in file|DB creds|Privileged group)' }).Count
      if ($hsN -gt 1) { Say ("  >> $hsN high-signal flag/cred/doc leads below -- CONFIRM ALL (don't action one and move on).") 'Red' }
      $rank = 0
      foreach($L in $ranked){
        $rank++
        $col = if ($L.Score -ge 85){'Red'} elseif ($L.Score -ge 70){'Yellow'} else {'Cyan'}
        Say ("  #{0} [{1}] {2}" -f $rank, $L.Score, $L.Title) $col
        Say ("       why: $($L.Why)") 'DarkGray'
        if ($rank -ge 15) { Say "  ...(+$($ranked.Count - 15) more leads above in their sections)" 'DarkGray'; break }
      }
    }
    Head "Coverage -- classes run this pass"
    foreach($c in $script:Classes){
      $_dc=[int]$script:ClassDenied[$c]; $_sk=[int]$script:ClassSkipped[$c]; $_er=[int]$script:ClassErrored[$c]
      $rsn = [string]$script:ClassErrReason[$c]
      if ($Loot) { $st = 'skipped (loot/root mode)' }
      elseif (Want $c) {
        if (-not $script:ScanCompleted) { $st = if ($script:AbortKind -eq 'error') { 'partial (run ended on a terminating error)' } else { 'partial (run interrupted before completion)' }; if (-not $rsn) { $rsn = if ($script:AbortKind -eq 'interrupt') { 'run interrupted (Ctrl-C) before this class completed' } elseif ($script:AbortKind -eq 'error') { "run ended on a terminating error before this class completed: $script:AbortError" } else { 'run ended before completion' } } }
        elseif ($_dc -gt 0 -or $_sk -gt 0 -or $_er -gt 0) {
          $parts = @(); if ($_dc -gt 0) { $parts += "$_dc denied" }; if ($_sk -gt 0) { $parts += "$_sk skipped: tool absent" }; if ($_er -gt 0) { $parts += "$_er error/timed_out" }
          $st = 'partial (' + ($parts -join ', ') + ')'
        } else { $st = 'complete' }
      }
      else { $st = 'skipped (-Only/-Skip)' }
      Info ("  {0,-12}: {1}" -f $c, $st)
      if ($rsn -and $st -like 'partial*') { Info ("               -> " + $rsn) }
    }
    Info "  'complete' = every DECLARED collector in a selected class ran to its end with NO denied access, NO tool-absent skip, and NO error/timeout (each recorded distinctly in JSON coverage/collectors). A Ctrl-C -> partial (abort_kind=interrupt); a terminating error aborts and is typed (abort_kind=error); a collector that exceeds WALDO_DEADLINE -> partial with a timed_out record. A best-effort probe that suppresses a NON-terminating error is treating an absent/inaccessible artifact as a clean negative -- the correct read-only outcome -- not a hidden gap."
    Write-JsonManifest
    Head "Done"
    Info "Leads are ranked guesses -- confirm each manually. Run WinPEAS alongside for full coverage."
  } catch { Write-Host "  [footer render error: $($_.Exception.Message)]" }
}
# Ctrl-C / unhandled error -> the finally still renders the footer + JSON exactly once (idempotent).
try {
# v0.48 §1 COV: bootstrap identity/context facts are 'id'-class content -- attribute their outcomes there so a failure
# marks the class partial (not a silent false/unknown default that skews ranking, filtering, and the A12 verdict).
$script:CurrentClass = 'id'; $script:CurrentCollector = 'bootstrap identity/context'
# SIDs the current token carries (user + groups + Everyone).
$script:MySids = @()
try {
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  $script:MySids += $me.User.Value
  foreach($g in $me.Groups){ $script:MySids += $g.Value }
} catch { CovError "current-token SID enumeration failed: $($_.Exception.Message)" }
$script:MySids += 'S-1-1-0'
$script:MySids = $script:MySids | Select-Object -Unique

# Elevation detection. When running as SYSTEM / elevated-admin, "writable" is trivially
# true for almost everything and is NOT a privesc finding -- so we suppress writable-based
# leads. The elevated pass is for post-exploitation COLLECTION; the low-priv pass is
# authoritative for escalation. (-LowPriv forces the writable checks back on.)
$script:Elevated = $false
$script:Ctx = 'standard user'
try {
  $meI = [Security.Principal.WindowsIdentity]::GetCurrent()
  if ($meI.User.Value -eq 'S-1-5-18') { $script:Elevated = $true; $script:Ctx = 'SYSTEM' }
  elseif (([Security.Principal.WindowsPrincipal]$meI).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $script:Elevated = $true; $script:Ctx = 'elevated admin' }
} catch { CovError "elevation detection failed: $($_.Exception.Message)" }
if ($LowPriv) { $script:Elevated = $false; $script:Ctx = "$($script:Ctx) (-LowPriv: writable checks forced ON)" }
# is the current identity a MACHINE ACCOUNT (HOST$)? SYSTEM on a domain box authenticates
# outward as COMPUTER$ -- changes what domain enumeration means. Detect + note DC vs member role.
$script:IsMachineAcct = $false; $script:IsDC = $false
try {
  $unow = try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "$env:USERDOMAIN\$env:USERNAME" }
  if ($script:Elevated -and ($env:USERNAME -match '\$$' -or "$env:COMPUTERNAME$" -ieq ($unow -replace '^.*\\',''))) { $script:IsMachineAcct = $true }
  $dr = [int](Get-Cim Win32_ComputerSystem).DomainRole   # 4=backup DC, 5=primary DC
  if ($dr -ge 4) { $script:IsDC = $true }
} catch { CovError "machine-account / DC-role detection failed: $($_.Exception.Message)" }

# v2.16 A12: effective token / UAC verdict -- integrity level + filtered-token, not just membership.
$script:IntegrityLevel = 'unknown'; $script:AdminMember = $false; $script:AdminDenyOnly = $false; $script:LATFP = $null
$script:IsDomainAdmin = $false; $script:IsEnterpriseAdmin = $false
try {
  foreach ($row in (& "$env:WINDIR\System32\whoami.exe" /groups /fo csv 2>$null | ConvertFrom-Csv)) {
    # v0.34 A12: integrity by RID RANGE (not four exact SIDs) so any valid mandatory-level RID classifies, never 'unknown'
    if ($row.SID -match '^S-1-16-(\d+)$') {
      $rid = [int]$Matches[1]
      $script:IntegrityLevel = if ($rid -ge 16384) {'system'} elseif ($rid -ge 12288) {'high'} elseif ($rid -ge 8192) {'medium'} elseif ($rid -ge 4096) {'low'} else {'untrusted'}
    }
    if ($row.SID -eq 'S-1-5-32-544') { $script:AdminMember = $true; if ($row.Attributes -match '(?i)deny') { $script:AdminDenyOnly = $true } }  # deny-only = filtered token
    if ($row.SID -match '^S-1-5-21-.+-512$') { $script:IsDomainAdmin = $true }       # Domain Admins
    if ($row.SID -match '^S-1-5-21-.+-519$') { $script:IsEnterpriseAdmin = $true }   # Enterprise Admins
  }
} catch { CovError "effective-token integrity/group classification (whoami /groups) failed: $($_.Exception.Message)" }
try { $script:LATFP = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -ErrorAction Stop).LocalAccountTokenFilterPolicy } catch {}
# v0.15 A12: real TOKEN elevation type + linked-token (GetTokenInformation) -- drives suppression by the ACTUAL token,
# not just IsInRole. Read-only query of our OWN token (no exploitation). Type 1=default/UAC-off, 2=full, 3=limited(filtered).
$script:ElevationType = 'unknown'; $script:HasLinkedToken = $false
try {
  if (-not ([System.Management.Automation.PSTypeName]'Waldo.Tok').Type) {
    Add-Type -Namespace Waldo -Name Tok -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true)]
public static extern bool GetTokenInformation(System.IntPtr TokenHandle, int TokenInformationClass, System.IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true)]
public static extern bool OpenProcessToken(System.IntPtr ProcessHandle, int DesiredAccess, out System.IntPtr TokenHandle);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetCurrentProcess();
'@ -ErrorAction Stop
  }
  $h = [IntPtr]::Zero
  if ([Waldo.Tok]::OpenProcessToken([Waldo.Tok]::GetCurrentProcess(), 0x8, [ref]$h)) {   # TOKEN_QUERY
    $p = [Runtime.InteropServices.Marshal]::AllocHGlobal(4); $rl = 0
    if ([Waldo.Tok]::GetTokenInformation($h, 18, $p, 4, [ref]$rl)) {                       # TokenElevationType = 18
      switch ([Runtime.InteropServices.Marshal]::ReadInt32($p)) {
        1 { $script:ElevationType = 'default (no UAC split -- standard user or UAC disabled)' }
        2 { $script:ElevationType = 'full (already elevated)' }
        3 { $script:ElevationType = 'limited (filtered token -- a linked FULL admin token exists)'; $script:HasLinkedToken = $true }
      }
    }
    [Runtime.InteropServices.Marshal]::FreeHGlobal($p)
  }
} catch { CovError "token elevation-type / linked-token query failed: $($_.Exception.Message)" }
if ($script:ElevationType -like 'full*') { $script:Elevated = $true }   # trust the token type over IsInRole
# TEST-ONLY hook (like WALDO_TRACK_PROSE): lets the COV injection KAT exercise the elevated-collection collectors
# without real elevation. Never set in production; it only flips the gate, it does not grant any privilege.
if ($env:WALDO_TEST_FORCE_ELEVATED) { $script:Elevated = $true; $script:Ctx = 'SYSTEM (test-forced -- COV injection only)' }
# v0.15 §4.1: Windows baseline family SELECTION + honest confidence. The ROLE (client/server/DC) changes what is stock
# (a DC's NTDS/DNS/Netlogon, a server's IIS/MSSQL are expected; on a client they'd be anomalies). Confidence reaches
# 'high' only when a role profile is SELECTED; a build with unknown role stays 'detected-generic'.
$script:BaselineFamily = 'unknown'; $script:BaselineConfidence = 'low'; $script:BaselineProfile = 'generic'; $script:BaselineRole = 'unknown'; $script:BaselineBuildName = 'unknown'; $script:RoleStockServices = @{}
try {
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $ptype = try { switch ([int](Get-Cim Win32_OperatingSystem).ProductType) { 1 {'client'} 2 {'domain-controller'} 3 {'server'} default {'unknown'} } } catch { 'unknown' }
  # v0.44 §4.1: reviewed BUILD recognition (names the build; deliberately does NOT drive any service/task subtraction --
  # see the design note below). A recognized build is a known reviewed baseline for RANKING/context, not suppression.
  $script:BaselineBuildName = switch ("$($cv.CurrentBuildNumber)") {
    '14393' {'Windows 10 1607 / Server 2016'} '17763' {'Windows 10 1809 / Server 2019'}
    '19044' {'Windows 10 21H2'} '19045' {'Windows 10 22H2'} '20348' {'Server 2022'}
    '22000' {'Windows 11 21H2'} '22621' {'Windows 11 22H2'} '22631' {'Windows 11 23H2'}
    '26100' {'Windows 11 24H2 / Server 2025'} default {"build $($cv.CurrentBuildNumber) (unreviewed)"}
  }
  if ($cv.CurrentBuildNumber -and $ptype -ne 'unknown') {
    $script:BaselineRole = $ptype
    $script:BaselineFamily = "windows $ptype ($script:BaselineBuildName)"
    # Role is RANKING CONTEXT only -- NOT an anomaly-suppression table. Only services that DEFINE the role (a DC is
    # AD DS by definition) are role-typical; OPTIONAL roles (IIS/MSSQL/DHCP/WDS) are NOT listed, because they are
    # frequently the anomaly that does not belong. A role-typical service is annotated but still fully evaluated.
    $_rss = switch ($ptype) {
      'domain-controller' { @('NTDS','Netlogon','Kdc','DFSR') }   # definitional AD DS services only
      default             { @() }                                  # server/client: no blanket role-typical subtraction
    }
    foreach($s in $_rss){ $script:RoleStockServices[$s.ToLower()] = $true }
    $script:BaselineProfile = "windows-$ptype / $script:BaselineBuildName (build recognized for context; GENERIC baseline BY DESIGN -- role/build drive ranking only, NO services/tasks subtracted from anomaly detection)"
    # v0.44 §4.1 DESIGN DECISION (auditor-sanctioned alternative): Windows intentionally ships a GENERIC role-detected
    # baseline, NOT per-build stock-service tables. An accurate default-service/task inventory is update- and role-
    # sensitive; an over-inclusive table would SUPPRESS a real anomaly (false negative) -- the worst failure for a
    # security tool. So the build/role are recognized for RANKING/context only and confidence stays 'role-detected'
    # (never 'high'); nothing is subtracted. The Linux SUID baseline, whose default set IS reviewable per version, does
    # carry reviewed per-version stock tables (-> 'high'). This split is documented in the spec (§4.1) and README.
    $script:BaselineConfidence = 'role-detected'
  } elseif ($cv.CurrentBuildNumber) {
    $script:BaselineFamily = "windows build $($cv.CurrentBuildNumber)"
    $script:BaselineProfile = 'generic (role unknown)'
    $script:BaselineConfidence = 'detected-generic'
  }
} catch { CovError "Windows baseline/build/role detection failed: $($_.Exception.Message)" }
# v0.34 A12: ONE effective-token verdict covering standard / local-admin / domain-admin / enterprise-admin / SYSTEM /
# outbound machine context / filtered / deny-only / integrity range / elevation+linked / LATFP -- no longer split across
# TokenVerdict + a later DA scope lead. SYSTEM's OUTBOUND identity is the machine account (COMPUTERNAME$), recognized
# even though the LOCAL identity is NT AUTHORITY\SYSTEM (not a HOST$ username).
$_domJoined = try { [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain } catch { $false }
$script:TokenVerdict = $(
  if ($script:IsEnterpriseAdmin) { "ENTERPRISE ADMIN token (forest-wide) [$($script:IntegrityLevel) integrity]" }
  elseif ($script:IsDomainAdmin) { "DOMAIN ADMIN token (domain-wide) [$($script:IntegrityLevel) integrity]" }
  elseif ($script:Ctx -eq 'SYSTEM' -and $script:IsDC) { "SYSTEM on DOMAIN CONTROLLER -- outbound = machine account $env:COMPUTERNAME`$ (NTDS-equivalent; DA not required)" }
  elseif ($script:Ctx -eq 'SYSTEM') { "SYSTEM (local, $($script:IntegrityLevel) integrity)$(if($_domJoined){" -- OUTBOUND network identity = machine account $env:COMPUTERNAME`$ (domain principal)"}else{' (workgroup: no domain machine account)'})" }
  elseif ($script:Elevated) { "high-integrity LOCAL ADMINISTRATOR ($($script:IntegrityLevel))" }
  elseif ($script:AdminMember) { "administrator member, FILTERED $($script:IntegrityLevel) token$(if($script:AdminDenyOnly){' (Administrators = deny-only)'}); elevation-type=$($script:ElevationType)" }
  else { "standard user ($($script:IntegrityLevel) integrity); elevation-type=$($script:ElevationType)" }
) + "$(if($script:HasLinkedToken){' ; linked FULL admin token available (UAC-elevatable)'})$(if($script:LATFP -eq 1){' ; LATFP=1 (remote logons get a full token)'})"
if (-not $script:Elevated -and ($script:AdminMember -or $script:HasLinkedToken)) {
  $_linked = if ($script:HasLinkedToken) { ' Token elevation-type is LIMITED: a linked FULL admin token exists -- elevate through UAC (elevated RunAs / a UAC bypass) to obtain it, no separate credential needed.' } else { '' }
  $_deny   = if ($script:AdminDenyOnly) { ' Administrators SID is present but DENY-ONLY (filtered network/UAC token) -- it grants nothing until you obtain a full token.' } else { '' }
  Add-Lead 60 "Filtered admin token ($($script:IntegrityLevel) integrity; type=$($script:ElevationType))" "You are in Administrators but hold a FILTERED $($script:IntegrityLevel)-integrity token (UAC) -- membership != high integrity. Obtain a full/high-integrity token before privileged collection; the low-priv writable findings below remain valid.$_linked$_deny$(if($script:LATFP -eq 1){' LocalAccountTokenFilterPolicy=1: remote logons get a full token.'})" -CanonicalSource 'filtered-admin-token' -Consumer 'current-token' -Primitive 'token-uac-filtered'
}

# Read-only ACL check for files, dirs, AND registry keys.
#   $true = writable, $false = not, $null = unknown/denied
#   When elevated, returns $false so writable-escalation false positives are suppressed.
function Test-Writable([string]$Path){
  if ($script:Elevated) { return $false }
  try {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    foreach($ace in $acl.Access){
      if ($ace.AccessControlType -ne 'Allow') { continue }
      $sid = $null
      try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
      catch { $sid = $ace.IdentityReference.Value }
      if ($script:MySids -contains $sid){
        $rights = $ace.FileSystemRights
        if (-not $rights) { $rights = $ace.RegistryRights }
        $rights = "$rights"
        if ($rights -match 'Write|Modify|FullControl|CreateFiles|AppendData|TakeOwnership|ChangePermissions|GenericAll|GenericWrite|SetValue|CreateSubKey'){
          return $true
        }
      }
    }
    return $false
  } catch { return $null }
}

# v0.15 A9: bounded walk UP a path's ancestors -- returns the highest writable ancestor (or a missing component
# whose existing parent is writable = creatable), else $null. Lets a writable GRANDPARENT / missing-intermediate dir
# surface even when the immediate dir is not writable. Bounded depth to stay cheap; read-only.
function Get-WritableAncestor([string]$path,[int]$max=6){
  if ($script:Elevated) { return $null }
  $cur = try { Split-Path $path -Parent } catch { $null }
  $depth = 0
  while ($cur -and $depth -lt $max) {
    if (Test-Path -LiteralPath $cur) {
      if ((Test-Writable $cur) -eq $true) { return @{ Dir=$cur; Kind='writable ancestor dir' } }
    } else {
      $par = try { Split-Path $cur -Parent } catch { $null }
      if ($par -and (Test-Path -LiteralPath $par) -and ((Test-Writable $par) -eq $true)) { return @{ Dir=$cur; Kind="missing intermediate dir (creatable from writable $par)" } }
    }
    $cur = try { Split-Path $cur -Parent } catch { $null }; $depth++
  }
  return $null
}

# Pull candidate executable/script/config paths out of a command line.
# Handles env vars, quoted paths, powershell -File, cmd /C, and bare script args.
function Extract-Targets([string]$cmd){
  $out = @()
  if (-not $cmd) { return $out }
  $c = [Environment]::ExpandEnvironmentVariables($cmd)
  foreach($m in [regex]::Matches($c,'"([A-Za-z]:\\[^"]+)"')){ $out += $m.Groups[1].Value }
  $m = [regex]::Match($c,'(?i)-File\s+"?([^"]+?\.(ps1|bat|cmd|vbs|js|wsf|py))"?(\s|$)'); if($m.Success){ $out += $m.Groups[1].Value }
  $m = [regex]::Match($c,'(?i)/[CK]\s+"?([A-Za-z]:\\[^"]+?\.(bat|cmd|exe|ps1|vbs|js))"?'); if($m.Success){ $out += $m.Groups[1].Value }
  foreach($m in [regex]::Matches($c,'([A-Za-z]:\\[^\s"]+?\.(exe|dll|ps1|bat|cmd|vbs|js|wsf|py|config|xml|ini|jar))')){ $out += $m.Groups[1].Value }
  $out | Where-Object { $_ } | Select-Object -Unique
}

# cheap text extraction from a flagged office/pdf doc (no Office/admin needed).
# docx/xlsx/pptx are zips -> read text XML parts & strip tags. pdf -> pdftotext else ASCII runs.
function Extract-DocText([string]$Path){
  try {
    $ext = ([IO.Path]::GetExtension($Path)).ToLower()
    if (@('.docx','.xlsx','.pptx') -contains $ext) {
      Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
      $zip = [IO.Compression.ZipFile]::OpenRead($Path)
      $sb = New-Object System.Text.StringBuilder
      foreach($e in $zip.Entries){
        if ($e.FullName -match '(?i)(word/document\.xml|xl/sharedStrings\.xml|xl/worksheets/.*\.xml|ppt/slides/slide.*\.xml|docProps/core\.xml)') {
          $sr = New-Object IO.StreamReader($e.Open()); $xml = $sr.ReadToEnd(); $sr.Close()
          [void]$sb.Append(((($xml -replace '<[^>]+>',' ') -replace '\s+',' ')))
        }
      }
      $zip.Dispose(); return $sb.ToString()
    } elseif ($ext -eq '.pdf') {
      $pt = Get-Command pdftotext -ErrorAction SilentlyContinue
      if ($pt) { return ((& pdftotext $Path - 2>$null) -join ' ') }
      $raw = [IO.File]::ReadAllText($Path,[Text.Encoding]::GetEncoding('ISO-8859-1'))
      return (([regex]::Matches($raw,'[\x20-\x7E]{5,}') | ForEach-Object { $_.Value }) -join ' ')
    }
  } catch {}
  return ''
}

# Grep a file for secrets. Prints hits; returns hit count; raises a lead for real configs.
function Peek-Secrets([string]$Path){
  $n = 0
  try {
    $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($fi.PSIsContainer) { return 0 }
    if ($fi.Length -eq 0) { return 0 }
    # operator artifact (our own tool/output, incl. waldo's own source) -- don't grep its contents as "creds"
    if ((Is-Operator $Path) -and -not $ShowOperatorLeads) { Note "operator artifact (content peek skipped): $Path"; return 0 }
    $ext = $fi.Extension.ToLower()
    # v0.15 A6: credential-SEMANTIC basename fires REGARDLESS of content grammar or file format -- must not be
    # skipped by the office/binary early-returns below. Deduped; emitted only if a content lead did not already fire.
    $credNamed = ($fi.Name -match '(?i)^(credentials?|creds|passwords?|secrets?|logins?|accounts?)\.(txt|md|csv|ini|cfg|conf|ya?ml|json|xlsx?|docx?|pptx?|ods|odt|kdbx?)$') -and ($Path -notmatch '(?i)[\\/](samples?|examples?|templates?)[\\/]')
    $emitCredNamed = {
      if ($credNamed -and -not $script:CredNamedSeen[$Path]) {
        $script:CredNamedSeen[$Path] = $true
        Jackpot "credential-named file (surfaced by basename, format-independent): $Path"
        Add-Lead 86 "[credential-named] $Path" "Filename is credential-semantic ($($fi.Name)) -- read it regardless of format (spreadsheet cells / structured rows carry creds and won't match a password= regex). Manual review." -CanonicalSource (Redact-ForId $Path) -Consumer 'filesystem' -Primitive 'credential-named-file'
        try { if ($ext -in '.txt','.md','.csv','.ini','.cfg','.conf','.yml','.yaml','.json') { Get-Content -LiteralPath $Path -TotalCount 6 -ErrorAction Stop | ForEach-Object { $ln=([string]$_).Trim(); if($ln){ Say ("         > $ln") 'Red' } } } } catch {}
        Add-CredArtifact 'credential-named file (review)' $Path
      }
    }
    # office/pdf docs -- Waldo already flagged the file; extract text & grep it
    if (@('.docx','.xlsx','.pptx','.pdf') -contains $ext -and -not $NoContent) {
      if ($fi.Length -gt 8MB) { & $emitCredNamed; return 0 }
      $dt = Extract-DocText $Path
      if (-not $dt) { & $emitCredNamed; return 0 }
      $ms = @([regex]::Matches($dt, $SecretRegex)) | Select-Object -First $MaxPeekLines
      if ($ms.Count -eq 0) { & $emitCredNamed; return 0 }
      foreach($m in $ms){ $v = $m.Value; if ($v.Length -gt 160) { $v = $v.Substring(0,160) + '...' }; Say ("         > doc secret? $v") 'Red' }
      Add-Lead 86 "[doc secret] $Path" "Text extracted from a flagged document contains credential-shaped content -- read the file. Manual review." -CanonicalSource (Redact-ForId $Path) -Consumer 'filesystem' -Primitive 'document-secret'
      Add-CredArtifact '[doc secret]' $Path
      return $ms.Count
    }
    if ($fi.Length -gt $MaxPeekBytes) { & $emitCredNamed; return 0 }
    if ($ext -match '\.(exe|dll|sys|png|jpg|jpeg|gif|ico|zip|7z|rar|gz|tar|tgz|msi|cab|pdb|mui|pfx|p12|jks|keystore|gpg|db|sqlite|sqlite3|mdf|kdbx|kdb|psafe3|opvault|walletx|xls|doc)$') { & $emitCredNamed; return 0 }
    $hits = Select-String -LiteralPath $Path -Pattern $SecretRegex -ErrorAction Stop | Select-Object -First $MaxPeekLines
    $sample = ''
    foreach($h in $hits){
      $line = ($h.Line).Trim()
      $sample += " $line"
      if ($line.Length -gt 160) { $line = $line.Substring(0,160) + '...' }
      Say ("         > creds? L$($h.LineNumber): $line") 'Red'
      $n++
    }
    if ($n -gt 0 -and $ext -ne '.log') {
      if ("$Path $sample" -match '(?i)db_pass|database|mysql|postgre|pgsql|mssql|sqlserver|jdbc|data source|connection ?string|wp-config|configuration\.php') { $script:DbCredHint += $Path }
      $ctype = Classify-Secret $sample
      $sc = Score-SecretHit $Path $sample
      if ($sc.Tag -eq '[operator] ' -and -not $ShowOperatorLeads) {
        Note "operator artifact (secret grep): $Path  [capped -- -ShowOperatorLeads to rank]"
        Add-Lead 40 "$($sc.Tag)Secrets in file: $Path" "Likely operator-created; type: $ctype. Manual review." -CanonicalSource (Redact-ForId "$($sc.Tag)") -Consumer 'secrets-in-file' -Primitive 'secrets-in-file'
      } else {
        Add-Lead $sc.Score "$($sc.Tag)Secrets in file: $Path" "Grep hit $n credential-shaped line(s) -- type: $ctype. Manual review." -CanonicalSource (Redact-ForId "$($sc.Tag)") -Consumer 'secrets-in-file' -Primitive 'secrets-in-file'
      }
      Add-CredArtifact $ctype $Path
    }
    else { & $emitCredNamed }   # v0.15 A6: content didn't match the secret grammar -> fall back to the format-independent basename rule
  } catch {}
  return $n
}

function Report-Path([string]$Path,[string]$Label){
  $w = Test-Writable $Path
  $tag = if ($Label){ "$Label -> $Path" } else { $Path }
  if     ($w -eq $true)  { Jackpot "$tag   [WRITABLE by you]" }
  elseif ($w -eq $null)  { Denied  "$tag   [access denied / unknown]" }
  else                   { Waldo   $tag }
  if (-not $NoContent) { [void](Peek-Secrets $Path) }
}

# v0.34 A9: empty-template negative. A stock/empty appsettings*.json / launchSettings.json (Logging+AllowedHosts
# scaffolding, no connection string or secret) is NOT a lead -- report a config file only when it actually carries a
# connection string / credential-shaped token, or when it is a config type that is inherently cred-bearing
# (.udl, *connectionStrings*.config, web.config with a <connectionStrings> section). Returns $true if reported.
function Report-ConfigPath([string]$Path,[string]$Label){
  $name = Split-Path $Path -Leaf
  $inherent = $name -match '(?i)(\.udl$|connectionStrings.*\.config$)'
  $interesting = $inherent
  if (-not $interesting) {
    $txt = try { Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue } catch { $null }
    if ($txt) { $interesting = $txt -match $script:CfgSecretRe }
  }
  if (-not $interesting) { return $false }
  Report-Path $Path $Label
  return $true
}

# Deep look at a directory: surface scripts/exes/configs, flag writable, peek text.
function Scan-Zone([string]$Root,[int]$Depth,[string]$Label){
  if (-not (Test-Path -LiteralPath $Root)) { return }
  $files = $null
  try {
    if ($script:HasDepth) { $files = Get-ChildItem -LiteralPath $Root -Recurse -Depth $Depth -File -Force -ErrorAction SilentlyContinue }
    else                  { $files = Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue }
  } catch { Denied "$Root not fully listable"; return }
  $count = 0
  foreach($f in $files){
    $ext = $f.Extension.ToLower()
    $isExe = $ExecExt -contains $ext
    $isCfg = $InterestingExt -contains $ext
    if (-not ($isExe -or $isCfg)) { continue }
    if ($count -ge $ZoneFileCap) { Note "   ...(zone scan capped at $ZoneFileCap files in $Root)"; break }
    $count++
    $w = Test-Writable $f.FullName
    if ($isExe) { Add-FlaggedBin $f.Name }
    if ($w -eq $true) {
      Jackpot "$Label $($f.FullName)   [WRITABLE]"
      Add-Lead 68 "Writable file in custom/app path: $($f.FullName)" "A $ext under $Root is writable by you -- possible code-execution condition if a privileged process runs/loads it. Manual review." -CanonicalSource (Redact-ForId "$($f.FullName)") -Consumer 'writable-file-in-custom-app-path' -Primitive 'writable-file-in-custom-app-path'
    } elseif ($isExe) {
      Waldo "$Label exe/script: $($f.FullName)"
    } else {
      Waldo "$Label $($f.FullName)"
    }
    if ($isCfg -and -not $NoContent) { [void](Peek-Secrets $f.FullName) }
  }
}

# LOOT MODE: offline triage of an already-pulled loot directory (TFTP/SMB/FTP/web pulls).
# Enumeration-only -- reads files you already have, no target interaction.
function Invoke-Loot([string]$Root){
  if (-not (Test-Path -LiteralPath $Root)) { Say "loot dir not found: $Root" 'Red'; return }
  Head "LOOT TRIAGE: $Root  (offline inventory of pulled files)"
  Info "Enumeration-only: reading already-pulled files; no target interaction."
  # auto-detect: is this actually a whole filesystem ROOT (mounted share)? point them at the structured sweep
  if ((Test-Path -LiteralPath "$Root\Windows\System32") -or (Test-Path -LiteralPath "$Root\etc\passwd")) {
    Jackpot "this looks like a full filesystem ROOT (mounted share), not a pile of pulled files."
    Info "  -> re-run with  -Root '$Root'  for the structured crown-jewel sweep (hives/RegBack/Windows.old, flags, per-user artifacts, writable drop-targets) instead of this blind recurse."
  }
  $n=0; $hits=0
  Get-ChildItem $Root -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First 4000 | ForEach-Object {
    if ($_.Length -eq 0) { return }
    $n++
    $ext = $_.Extension.ToLower()
    if ($InterestingExt -contains $ext -or $ExecExt -contains $ext) { Report-Path $_.FullName 'loot'; $hits++ }
    else {
      try { if (Select-String -LiteralPath $_.FullName -Pattern $SecretRegex -Quiet -ErrorAction Stop) { Waldo "loot (secret in oddly-named file): $($_.FullName)"; [void](Peek-Secrets $_.FullName); $hits++ } } catch {}
    }
  }
  Info "loot files inventoried: $n ; interesting/secret-bearing: $hits"
}

# ROOT TRIAGE: point Waldo at a MOUNTED target filesystem root (e.g. a shared-out C:\ via net use Z: \\host\C$).
# Re-roots the crown-jewel path intelligence at $Root. Enumeration-only: reads over the mount, writes nothing.
function Invoke-RootTriage([string]$Root){
  $Root = $Root.TrimEnd('\')
  $winTree = Test-Path -LiteralPath "$Root\Windows\System32"
  $nixTree = (Test-Path -LiteralPath "$Root\etc\passwd") -or (Test-Path -LiteralPath "$Root\etc\shadow")
  if (-not $winTree) {
    Head "ROOT TRIAGE: $Root"
    if ($nixTree) { Info "Linux filesystem tree detected -- the structured Linux root-triage ships next; running the generic loot recurse for now." }
    else { Info "No Windows tree (Windows\System32) here -- running the generic loot recurse instead." }
    Invoke-Loot $Root; return
  }
  Head "ROOT TRIAGE (shared/mounted Windows filesystem): $Root"
  Info "Enumeration-only: reading files over the mount, writing nothing. Host-context (your identity/live services/AD) is skipped -- this describes the REMOTE box's disk, not yours."
  $shareWritable = (Test-Writable $Root) -eq $true
  if ($shareWritable) { Jackpot "the mounted root is WRITABLE by you -> drop-to-execute conditions flagged below (Waldo places nothing)"; Add-Lead 82 "Writable mounted filesystem root: $Root" "The share is writable -- re-rooted Startup/service/task paths become drop-to-execute. Manual review (Waldo writes nothing)." -CanonicalSource (Redact-ForId "$Root") -Consumer 'writable-mounted-filesystem-root' -Primitive 'writable-mounted-filesystem-root' }

  function Test-Readable([string]$p){ if (-not (Test-Path -LiteralPath $p)) { return 'absent' }; try { $fs=[IO.File]::Open($p,'Open','Read','None'); $fs.Close(); 'readable' } catch { 'locked' } }

  # 1. Registry hives -- the crown jewel: on a share these are often UNLOCKED files -> offline secretsdump (no cracking for PtH)
  Sub "Registry hives (readable = offline hash/LSA dump, no cracking needed for pass-the-hash)"
  $hiveSets = @(
    @("$Root\Windows\System32\config",'live'),
    @("$Root\Windows\System32\config\RegBack",'RegBack (often unlocked)'),
    @("$Root\Windows.old\Windows\System32\config",'Windows.old (unlocked)') )
  $gotHive = $false
  foreach($hs in $hiveSets){
    foreach($h in @('SAM','SYSTEM','SECURITY','SOFTWARE')){
      $p = Join-Path $hs[0] $h
      switch (Test-Readable $p) {
        'readable' { Jackpot "READABLE hive: $p  [$($hs[1])]"; if (@('SAM','SYSTEM','SECURITY') -contains $h) { $gotHive = $true }; Add-CredArtifact "registry hive ($($hs[1]))" $p }
        'locked'   { Note "hive present but LOCKED (live box): $p -- try RegBack / Windows.old / a VSS copy" }
      }
    }
  }
  if ($gotHive) { Add-Lead 95 "Registry hives readable on the share" "SAM + SYSTEM (+SECURITY) readable over the mount -- copy them and run secretsdump LOCAL offline to recover local hashes & LSA secrets (LSA often holds DOMAIN/service creds). Preserve each as an exact pair with origin scope; any use is your manual decision. Waldo does not test/reuse." -CanonicalSource 'share-registry-hives' -Consumer 'mounted-share' -Primitive 'offline-hash-dump' }
  else { Info "No readable SAM/SYSTEM/SECURITY set (live hives lock even over a share -- RegBack/Windows.old/VSS are the unlocked options)." }
  $ntds = "$Root\Windows\NTDS\ntds.dit"
  if ((Test-Readable $ntds) -eq 'readable') { Jackpot "READABLE ntds.dit: $ntds"; Add-Lead 98 "NTDS.dit readable on the share (DC disk)" "ntds.dit + the SYSTEM hive = full DOMAIN hash dump offline (secretsdump -ntds ntds.dit -system SYSTEM LOCAL). Manual review." -CanonicalSource 'share-ntds-dit' -Consumer 'mounted-share' -Primitive 'domain-hash-dump'; Add-CredArtifact 'NTDS.dit (domain hashes, offline)' $ntds }

  # 2. Flags (incl. Administrator's desktop, unreadable from a normal shell)
  Sub "Flags on user desktops"
  Get-ChildItem "$Root\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    foreach($f in @('proof.txt','local.txt','flag.txt','root.txt','user.txt')){
      $fp = Join-Path $_.FullName "Desktop\$f"
      if (Test-Path -LiteralPath $fp) { Jackpot "FLAG: $fp"; Add-Lead 90 "Flag readable on share: $fp" "Objective readable over the MOUNT -- this is a mounted copy, NOT submission proof: reopen it on the ORIGINAL target in an interactive shell (type/cat) with IP context." -CanonicalSource (Redact-ForId "$fp") -Consumer 'flag-readable-on-share' -Primitive 'flag-readable-on-share'; try { Note ("      " + (Get-Content -LiteralPath $fp -TotalCount 1 -ErrorAction Stop)) } catch {} }
    }
  }

  # 3. Per-user credential artifacts, re-rooted
  Sub "Per-user artifacts (.ssh / history / saved sessions / vaults / NTUSER.DAT)"
  Get-ChildItem "$Root\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' } | ForEach-Object {
    $u = $_.FullName
    foreach($rel in @('.ssh\id_rsa','.ssh\id_ed25519','.ssh\id_dsa','.ssh\config','.ssh\known_hosts','.ssh\authorized_keys',
      'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
      'AppData\Roaming\WinSCP.ini','AppData\Roaming\FileZilla\sitemanager.xml','AppData\Roaming\FileZilla\recentservers.xml',
      'AppData\Local\Google\Chrome\User Data\Default\Login Data','NTUSER.DAT')){
      $p = Join-Path $u $rel
      if (Test-Path -LiteralPath $p) { Report-Path $p 'root-user' }
    }
    Get-ChildItem $u -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue -Include '*.kdbx','*.rdp','*.ppk','id_rsa','*.pem' | Select-Object -First 20 | ForEach-Object { Report-Path $_.FullName 'root-user' }
  }

  # 4. Provisioning / answer files
  Sub "Provisioning / answer files"
  foreach($p in @("$Root\unattend.xml","$Root\autounattend.xml","$Root\Windows\Panther\Unattend.xml","$Root\Windows\Panther\Unattended.xml","$Root\Windows\System32\Sysprep\unattend.xml","$Root\Windows\Panther\setupact.log")){
    if (Test-Path -LiteralPath $p) { Report-Path $p 'root-prov' }
  }

  # 5. Web app roots & configs
  Sub "Web app roots & configs"
  foreach($wr in @("$Root\inetpub\wwwroot","$Root\xampp\htdocs","$Root\wamp\www","$Root\wamp64\www","$Root\laragon\www","$Root\www","$Root\wwwroot")){
    if (-not (Test-Path -LiteralPath $wr)) { continue }
    Get-ChildItem $wr -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue -Include 'web.config','wp-config.php','configuration.php','config.php','database.php','settings.php','.env','appsettings*.json','connectionStrings*.config' | Select-Object -First 40 | ForEach-Object { Report-Path $_.FullName 'root-web' }
  }

  # 6. Writable drop-to-execute targets (only if the share is writable)
  if ($shareWritable) {
    Sub "Writable autostart drop-targets (share is writable -> code-exec at logon)"
    $dropDirs = @("$Root\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    Get-ChildItem "$Root\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $dropDirs += (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }
    foreach($d in ($dropDirs | Select-Object -Unique)){
      if ((Test-Path -LiteralPath $d) -and (Test-Writable $d) -eq $true) { Jackpot "WRITABLE Startup on share: $d"; Add-Lead 86 "Writable Startup folder on share: $d" "You can write to a Startup folder over the mount -- a dropped exe/lnk runs at that user's next logon (as them). Manual review (Waldo drops nothing)." -CanonicalSource (Redact-ForId "$d") -Consumer 'writable-startup-folder-on-share' -Primitive 'writable-startup-folder-on-share' }
    }
  }

  # 7. bounded secret sweep of the high-value subtree (NOT all of Windows\)
  Sub "Bounded secret sweep (Users / ProgramData / inetpub -- skips Windows\ noise)"
  $sn=0
  foreach($s in (@("$Root\Users","$Root\ProgramData","$Root\inetpub") | Where-Object { Test-Path -LiteralPath $_ })){
    Get-ChildItem $s -Recurse -Depth 5 -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 -and $_.Length -lt 5MB -and ($InterestingExt -contains $_.Extension.ToLower()) } | Select-Object -First 400 | ForEach-Object { Report-Path $_.FullName 'root-sweep'; $sn++ }
  }
  Info "root triage complete ($sn high-value files swept). Confirm/pull manually -- Waldo touched nothing."
}

# =====================================================================
#  BANNER
# =====================================================================
Say ""
Say "          .-------------------------------------." 'DarkYellow'
Say "          |  W H E R E ' S   W A L D O ?  (Win)  |" 'Yellow'
Say "          '-------------------------------------'" 'DarkYellow'
Say "   Enumeration by anomaly. Read-only. Correlates anomalies into ranked leads." 'DarkGray'
Say "   Legend: [!]=nonstandard  [!!]=nonstandard+WRITABLE  [x]=denied  [i]=info" 'DarkGray'
Say "   lab-safe: enumeration-only local triage. Does NOT exploit, modify services/" 'DarkGray'
Say "   tasks, write payloads, brute force, scan the network, or validate CVEs. Every" 'DarkGray'
Say "   finding is a local observation that requires manual verification." 'DarkGray'
if ($script:Elevated) {
  Say ""
  Say "   *** MODE: ELEVATED ($($script:Ctx)) -- writable-escalation findings SUPPRESSED ***" 'Red'
  Say "   (writability is trivially true at this privilege). This pass = post-exploitation" 'Red'
  Say "   collection & visibility (protected creds, other users' data, hives, event logs)." 'Red'
  Say "   Re-run as the LOW-PRIV user for authoritative privesc findings. (-LowPriv overrides.)" 'Red'
} else {
  Say "   MODE: standard user -- writable checks active (authoritative for privesc)." 'DarkGray'
}

# LOOT MODE short-circuit: triage a pulled-file directory, then jump to the ranked summaries.
if ($script:RootMode) { Invoke-RootTriage $Root } elseif ($Loot) { Invoke-Loot $Loot }

# =====================================================================
#  0. HOST FACTS + CURRENT CONTEXT
# =====================================================================
if (-not $Loot) {
Head "Host & current context"
$script:CurrentClass = 'id'   # COV: the always-on host-context section (token, whoami /priv, etc.) is 'id'-class content -- attribute its outcomes there, not to an empty class
$script:DomainJoined = $false
try {
  $os = Get-Cim Win32_OperatingSystem
  $cs = Get-Cim Win32_ComputerSystem
  $script:DomainJoined = [bool]$cs.PartOfDomain -and ($cs.Domain -and $cs.Domain -ne 'WORKGROUP')
  if ($script:DomainJoined) { Info "DOMAIN-JOINED: $($cs.Domain) -- preserve looted local/admin hashes as exact pairs with origin scope; corroborate before crossing to domain/DC (Waldo does not test/reuse)." }
  Info "Host      : $($env:COMPUTERNAME)   (domain/workgroup: $($cs.Domain))"
  Info "OS        : $($os.Caption)  build $($os.BuildNumber)  [$($os.OSArchitecture)]"
  Info "Baseline  : family=$($script:BaselineFamily) profile=$($script:BaselineProfile) confidence=$($script:BaselineConfidence)"
  if ($script:BaselineConfidence -eq 'low') { Info "            (unknown baseline -- 'non-standard' flags may include stock items; read with caution)" }
  elseif ($script:BaselineConfidence -eq 'detected-generic') { Info "            (role unknown -- verify flagged services against a clean box of this role)" }
  elseif ($script:BaselineConfidence -eq 'role-detected') { Info "            (role used for ranking context only; optional roles like IIS/MSSQL are NOT suppressed -- they are often the anomaly)" }
  Info "Installed : $($os.InstallDate)"
  Info "User      : $($env:USERDOMAIN)\$($env:USERNAME)"
  # Defender state + hotfix recency -- context facts, not a CVE runner
  try {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
      $rt = if ($mp.RealTimeProtectionEnabled) { 'ON' } else { 'OFF' }
      if (-not $mp.RealTimeProtectionEnabled) { Waldo "Defender real-time protection: OFF"; Add-Lead 55 "Defender real-time protection OFF" "AV real-time protection is disabled -- note it (affects your tradecraft choices). Manual review." -CanonicalSource 'defender-realtime-off' -Consumer 'host-av-posture' -Primitive 'posture-av-disabled' }
      else { Note "Defender real-time: $rt (AntiMalware $($mp.AMProductVersion), sigs $($mp.AntivirusSignatureLastUpdated))" }
    } else { Note "Defender status: not queryable (may be third-party AV or disabled)" }
    $hf = Get-Cim Win32_QuickFixEngineering | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hf) { Note "Latest hotfix: $($hf.HotFixID) installed $($hf.InstalledOn) (patch-age context for manual research)" }
    else { Note "Hotfix history: none visible (unpatched-looking or access denied -- worth a manual patch-level check)" }
  } catch {}
} catch { CovError "host/OS facts (Win32_OperatingSystem/ComputerSystem) failed: $($_.Exception.Message)" }
try {
  Sub "whoami /groups (high-value groups + what they buy)"
  $groupCards = [ordered]@{
    'Backup Operators'  = 'SeBackup/SeRestore -- read ANY file incl. locked hives: reg save HKLM\SAM & HKLM\SYSTEM, or robocopy /B protected files/NTDS/proof paths, then secretsdump LOCAL.'
    'Server Operators'  = 'reconfigure/start a SYSTEM service (sc config <svc> binPath=...), or manage shares.'
    'Account Operators' = 'reset passwords / add members on most non-admin domain accounts & groups.'
    'DnsAdmins'         = 'load an arbitrary DLL into the DNS service (dnscmd /config ...serverlevelplugindll) -> SYSTEM on the DNS host (often the DC).'
    'Print Operators'   = 'SeLoadDriver -> load a driver for SYSTEM.'
    'Remote Management' = 'WinRM access (evil-winrm) -- execution, NOT necessarily local admin.'
    'Hyper-V'           = 'manipulate VMs / virtual disks -> offline attack on guest hives.'
  }
  $allGroups = @(whoami /groups 2>$null | Where-Object { $_ -match '\S' -and $_ -notmatch '^(GROUP INFORMATION|-----|Group Name)' })
  foreach($gl in $allGroups){
    $ln = $gl.Trim()
    $hi = $ln -match 'Admin|Backup Operators|Server Operators|Remote Desktop|Remote Management|DnsAdmins|Hyper-V|Print Operators|Account Operators'
    if ($hi) { Waldo $ln } else { Note $ln }   # full roster: highlight priv groups, list the rest for your notes
    foreach($k in $groupCards.Keys){ if ($ln -match [regex]::Escape($k)) { Jackpot "  ^ $k -> $($groupCards[$k])"; Add-Lead 88 "Privileged group membership: $k" "You are in '$k'. $($groupCards[$k]) Manual review (no exploit run)." -CanonicalSource (Redact-ForId "$k") -Consumer 'privileged-group-membership' -Primitive 'privileged-group-membership' } }
  }
  # Full local group -> member roster (note-taking: which account is in which privileged group)
  Sub "Local groups & members (full roster)"
  try {
    $lgroups = @()
    try { $lgroups = Get-LocalGroup -ErrorAction Stop | Select-Object -ExpandProperty Name } catch {
      $lgroups = (net localgroup 2>$null) | Where-Object { $_ -match '^\*' } | ForEach-Object { ($_ -replace '^\*','').Trim() }
    }
    foreach($g in $lgroups){
      $mem = @()
      try { $mem = Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { $_.Name } } catch {
        $mem = (net localgroup "$g" 2>$null) | Where-Object { $_ -and $_ -notmatch 'command completed|Alias name|Comment|Members|^-+$' } | ForEach-Object { $_.Trim() }
      }
      if ($mem.Count -gt 0) {
        $priv = $g -match 'Admin|Backup Operators|Server Operators|Remote Desktop|Remote Management|DnsAdmins|Hyper-V|Print Operators|Account Operators'
        if ($priv) { Waldo "$g : $($mem -join ', ')" } else { Note "$g : $($mem -join ', ')" }
      }
    }
  } catch { CovSkip "local group enumeration unavailable ($($_.Exception.Message))" }
  # LOCKOUT / PASSWORD POLICY -- source-aware. CRITICAL before spraying (threshold + observation window).
  Sub "Account lockout & password policy (know this BEFORE any credential testing)"
  try {
    $na = @(net accounts 2>$null)
    $get = { param($rx) ($na | Select-String $rx | Select-Object -First 1) -replace '.*:\s*','' -replace '\s+$','' }
    $thr = (& $get 'Lockout threshold'); $obs = (& $get 'Lockout observation window'); $dur = (& $get 'Lockout duration')
    $minlen = (& $get 'Minimum password length'); $maxage = (& $get 'Maximum password age')
    Info "[LOCAL SAM policy] (governs LOCAL accounts on this host):"
    Note "   lockout threshold=$thr ; observation window=$obs ; lockout duration=$dur ; min pw len=$minlen ; max pw age=$maxage"
    if ($thr -match 'Never|^0') { Add-Lead 40 "[LOCAL] No account lockout" "Local lockout threshold is Never/0 -- LOCAL accounts do not lock out. Posture fact only; Waldo does not guess or spray." -CanonicalSource 'local-account-lockout-policy' -Consumer 'local-sam-policy' -Primitive 'posture-no-lockout' }
    elseif ($thr) { Add-Lead 42 "[LOCAL] Lockout threshold=$thr" "LOCAL accounts lock after $thr bad tries (window=$obs). Posture fact only -- Waldo tests nothing; lockout risk is your manual consideration." -CanonicalSource 'local-account-lockout-policy' -Consumer 'local-sam-policy' -Primitive 'posture-lockout' }
  } catch { CovError "local account lockout/password policy (net accounts) failed: $($_.Exception.Message)" }
  if ($script:DomainJoined) {
    Info "This host is DOMAIN-JOINED: DOMAIN accounts follow the DOMAIN policy (below / via -AD), which OVERRIDES the local SAM for domain logons. `net accounts /domain` also shows it."
    try {
      $nad = @(net accounts /domain 2>$null)
      if ($nad -and ($nad -notmatch 'error|not found')) {
        $getd = { param($rx) ($nad | Select-String $rx | Select-Object -First 1) -replace '.*:\s*','' -replace '\s+$','' }
        Note "   [DOMAIN via net] threshold=$(& $getd 'Lockout threshold') ; window=$(& $getd 'Lockout observation window') ; duration=$(& $getd 'Lockout duration') ; min pw len=$(& $getd 'Minimum password length')"
      }
    } catch {}
  }
  Sub "whoami /priv (privileges of interest)"
  $privCards = [ordered]@{
    'SeImpersonate' = 'Potato-family (JuicyPotato/PrintSpoofer/GodPotato) -> SYSTEM.'
    'SeAssignPrimaryToken' = 'token assignment -> Potato-family -> SYSTEM.'
    'SeBackup' = 'read ANY file incl. locked hives: reg save HKLM\SAM & HKLM\SYSTEM (or robocopy /B) -> secretsdump LOCAL.'
    'SeRestore' = 'write ANY file/registry -> overwrite a service binary or IFEO -> SYSTEM.'
    'SeDebug' = 'open any process -> dump LSASS / inject.'
    'SeTakeOwnership' = 'take ownership of any object, then grant yourself write.'
    'SeLoadDriver' = 'load a driver -> kernel/SYSTEM.'
    'SeManageVolume' = 'volume access -> arbitrary-path file read/write.'
    'SeTcb' = 'act as part of the OS -> SYSTEM.'
    'SeCreateToken' = 'craft a token -> SYSTEM.'
  }
  $privRaw = try { @(whoami /priv 2>$null) } catch { @() }
  if (-not $privRaw -or $privRaw.Count -eq 0) { CovError "whoami /priv produced no output -- privilege picture incomplete" }
  $privRaw | Select-String -Pattern (($privCards.Keys) -join '|') | ForEach-Object {
    $t = $_.Line.Trim(); Jackpot $t
    $priv = ($t -replace '\s+.*','')
    $card = ''; foreach($k in $privCards.Keys){ if ($priv -match $k) { $card = $privCards[$k]; break } }
    # already-elevated => this is moot; demote so real collection leads float
    $sc = if ($script:Elevated) { 30 } else { 90 }
    Add-Lead $sc "Privilege of interest held: $priv$(if($script:Elevated){' (moot -- already elevated)'})" "$card Manual review (no exploit run)." -CanonicalSource (Redact-ForId "$priv") -Consumer 'privilege-of-interest-held' -Primitive 'privilege-of-interest-held'
    if (-not $script:Elevated) { $_pc = if ($priv -match 'SeImpersonate|SeAssignPrimaryToken|SeRestore|SeLoadDriver|SeTcb|SeCreateToken|SeTakeOwnership') { 'shell' } else { 'read' }; Add-Primitive $_pc "token privilege $priv held" }
  }
} catch { CovError "privilege/group context (whoami /priv) failed: $($_.Exception.Message)" }
# foothold-vs-admin verdict -- NXC 'Pwn3d!' via WinRM is EXECUTION, not local admin. Set the next move.
try {
  $hasSe = [bool]((whoami /priv 2>$null) | Select-String -Pattern 'SeImpersonate|SeDebug|SeBackup|SeRestore|SeLoadDriver|SeTakeOwnership')
  if (-not $script:Elevated -and -not $hasSe) {
    Info "VERDICT: domain foothold / standard user -- NOT local admin, no impersonation/backup/debug priv. LSASS & live hives are LOCKED. Next move: readable files, your own profile, the privileged-group cards above, and AD outbound edges (run with -AD). Do NOT burn time on LSASS/hive dumps here."
  } elseif ($script:Elevated) {
    Info "VERDICT: elevated context -- collect (flags, LSASS, hives, SAM/SECURITY, configs, docs). Privilege leads are moot."
  }
  # credential SCOPE -- don't over-assume. Read-only from the current token SIDs.
  $isLocalAdmin = $script:Elevated -and -not $script:IsMachineAcct
  $isDA = [bool]($script:MySids | Where-Object { $_ -match '-512$' -or $_ -match '-519$' })  # Domain/Enterprise Admins RID
  $scopeBits = @()
  $scopeBits += "local admin here: $(if($isLocalAdmin){'YES'}elseif($script:Elevated){'YES (SYSTEM/machine)'}else{'no'})"
  if ($script:DomainJoined) { $scopeBits += "domain-valid: yes"; $scopeBits += "domain admin: $(if($isDA){'YES'}else{'not via this token (unknown for other creds)'})" }
  Info ("SCOPE: " + ($scopeBits -join '  |  ') + "  -- creds valid here are NOT proven valid/admin elsewhere; verify per-host, don't over-assume.")
  if ($isDA) { Jackpot "You (or your groups) are in Domain/Enterprise Admins."; Add-Lead 96 "Domain Admin token" "Current token carries Domain/Enterprise Admins -- you effectively own the domain (DCSync / any host). Confirm and collect. Manual review." -CanonicalSource 'domain-admin-token' -Consumer 'current-token' -Primitive 'token-domain-admin' }
  # machine-account / DC context labeling (SYSTEM on a DC authenticates as HOST$ on the domain)
  if ($script:IsMachineAcct) {
    if ($script:IsDC) { Jackpot "CONTEXT: SYSTEM on a DOMAIN CONTROLLER = machine account $env:COMPUTERNAME`$. This is DC01`$-equivalent: read NTDS.dit + SYSTEM = full domain, or DCSync locally. That's often ENOUGH -- Domain Admin may be unnecessary."; Add-Lead 97 "SYSTEM on DC (machine account $env:COMPUTERNAME`$)" "You are SYSTEM on the domain controller (as $env:COMPUTERNAME`$). NTDS.dit + SYSTEM hive -> secretsdump -ntds LOCAL = every domain hash. Objective likely met here; don't chase DA. Manual review." -CanonicalSource 'system-on-dc' -Consumer 'domain-controller' -Primitive 'domain-compromise-ntds' }
    else { Info "CONTEXT: SYSTEM on a domain MEMBER = machine account $env:COMPUTERNAME`$. The computer account has domain READ (LDAP/SMB) + can be used for BloodHound; local admin hash reuse to other hosts usually fails. Facts only." }
  }
  # consolidated post-admin CREDENTIAL-SOURCE checklist. Sources + prereqs, no extraction commands.
  if ($script:Elevated) {
    Sub "Credential-source checklist (you are admin/SYSTEM -- where creds live here)"
    $lssPid = try { (Get-Process lsass -ErrorAction SilentlyContinue).Id } catch { $null }
    Info "  [ ] LSASS $(if($lssPid){"(PID $lssPid)"}) -- logged-on/cached creds in memory (often the pivot to the next host). Dump OFFLINE, parse on Kali."
    # Credential Guard state -- if on, LSASS creds are protected
    try {
      $cg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
      $cgd = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning
      if ($cg -ge 1 -or ($cgd -contains 1)) { Info "  [!] Credential Guard appears ENABLED -- LSASS plaintext/NTLM is protected; pivot to DPAPI/hives/SAM/tickets instead." }
      else { Info "  [ ] Credential Guard: not detected -- LSASS creds likely extractable." }
    } catch {}
    Info "  [ ] SAM + SYSTEM hives -> local account hashes (reg save / already have SeBackup)."
    Info "  [ ] SECURITY + SYSTEM -> LSA secrets: _SC_<svc> service creds (often DOMAIN), cached domain logons (DCC2)."
    Info "  [ ] DPAPI / user profile vaults -> saved browser/RDP/Wi-Fi creds (Users\*\AppData\...\Protect)."
    Info "  [ ] Local app DBs / configs (see DB section) -- a local app DB often holds a creds table (remote login may fail while local access works)."
  }
  # DC-aware ranking mode for the LOW-PRIV-on-DC case (SYSTEM-on-DC handled above)
  if ($script:IsDC -and -not $script:Elevated) {
    Info "CONTEXT: low-privilege on a DOMAIN CONTROLLER. SYSTEM here = the whole domain (NTDS), so the goal is LOCAL SYSTEM on THIS box -- prioritize: local flag visibility, SeImpersonate/priv context, active sessions, local-admin/profile paths, GPO/ACL facts. SYSTEM-on-DC is usually ENOUGH; you likely do NOT need Domain Admin. Deprioritize generic AD group-control noise."
    Add-Lead 80 "Low-priv on a DC -> local SYSTEM is the objective" "You are non-admin on the domain controller. SYSTEM on the DC yields NTDS.dit = every domain hash, which is normally the objective (DA not required). Focus this host's local privesc (SeImpersonate/service/autostart/hive) over broad AD enumeration. Manual review." -CanonicalSource 'dc-local-system-objective' -Consumer 'domain-controller' -Primitive 'privesc-target-dc'
  }
} catch { CovError "foothold/elevation verdict + credential-scope context failed: $($_.Exception.Message)" }
# active sessions -- who else is logged on (situational awareness; NO session abuse).
# Runs in BOTH elevated and non-elevated context; an active privileged user is a high-value FACT.
if (Want 'users') {
try {
  Head "Active sessions (logged-on users -- who is here besides you)"
  Info "Observation only: Waldo never touches another session. An active admin/DA here is worth noting."
  $me = "$env:USERNAME"
  $seen = @{}
  # RDP/console/service sessions via qwinsta; fall back to query user
  $sess = @()
  try { $sess = (qwinsta 2>$null) } catch {}
  if (-not $sess) { try { $sess = (query user 2>$null) } catch {} }
  $sess | Where-Object { $_ -and $_ -notmatch 'SESSIONNAME|USERNAME' } | ForEach-Object { Note ("session: " + ($_.Trim())) }
  # Logged-on user accounts (WMI) -- classify against privileged local/domain groups
  $adminMembers = @{}
  try { (net localgroup Administrators 2>$null) | Where-Object { $_ -and $_ -notmatch 'command completed|Alias name|Comment|Members|^-+$' } | ForEach-Object { $adminMembers[($_.Trim().ToLower())] = $true } } catch {}
  try {
    Get-Cim Win32_LoggedOnUser | ForEach-Object {
      $a = $_.Antecedent
      if ($a -and $a -match 'Name="([^"]+)".*Domain="([^"]+)"') {
        $u = $Matches[1]; $d = $Matches[2]
        $key = "$d\$u".ToLower()
        if ($seen[$key]) { return }; $seen[$key] = $true
        if ($u -match '\$$') { return }  # machine accounts
        $priv = ''
        if ($adminMembers.ContainsKey($u.ToLower()) -or $adminMembers.ContainsKey("$d\$u".ToLower())) { $priv = ' [LOCAL ADMIN]' }
        if ($u -match '(?i)^(administrator|admin|da_|adm_|.*_da|svc[-_]|backup|deploy|ansible|operator)') { $priv += ' [privileged-looking name]' }
        if ($u -ieq $me) { Note "logged on: $d\$u (you)" }
        elseif ($priv) { Jackpot "logged on: $d\$u$priv"; Add-Lead 72 "Privileged user session present: $d\$u" "Another privileged/admin-looking user ($d\$u) is logged on this host$priv. Situational awareness only -- if you later gain SYSTEM, their creds may be in memory. Waldo does nothing to the session." -CanonicalSource (Redact-ForId "$d") -Consumer 'privileged-user-session-present' -Primitive 'privileged-user-session-present' }
        else { Waldo "logged on: $d\$u (other user session)" }
      }
    }
  } catch { CovError "logged-on-user enumeration (Win32_LoggedOnUser) failed: $($_.Exception.Message)" }
} catch { CovError "active-sessions collector failed: $($_.Exception.Message)" }
}
}   # end host-context (skipped in loot mode)

# =====================================================================
#  NETWORK -- interfaces, routes, DUAL-HOMED (pivot indicator)
# =====================================================================
if (Want 'id') {
Head "Network -- interfaces & routes (dual-homed = pivot)"
# C3: compute the REAL network address (ip masked by its subnet mask, with prefix) -- no /24 assumption.
function script:Get-IpNet($ip,$mask){ try { $ib=[System.Net.IPAddress]::Parse($ip).GetAddressBytes(); $mb=[System.Net.IPAddress]::Parse($mask).GetAddressBytes(); $nb=for($i=0;$i -lt 4;$i++){ $ib[$i]-band $mb[$i] }; $pfx=(($mb|ForEach-Object{[Convert]::ToString($_,2)}) -join '').Replace('0','').Length; "$($nb -join '.')/$pfx" } catch { $null } }
try {
  $ips = @(); $nets = @()
  foreach ($a in (Get-Cim Win32_NetworkAdapterConfiguration "IPEnabled=True")) {
    $mlist = @($a.IPSubnet)
    $idx = 0
    foreach ($ip in @($a.IPAddress)) {
      if ($ip -match '^\d+\.\d+\.\d+\.\d+$' -and $ip -notmatch '^(127\.|169\.254\.)') {
        $ips += $ip
        $mask = if ($idx -lt $mlist.Count) { $mlist[$idx] } else { '255.255.255.0' }
        $rn = script:Get-IpNet $ip $mask; if ($rn) { $nets += $rn }   # REAL network (prefix from the mask), not the stripped last octet
        Info ("iface: {0} | ip {1} | mask {2} | gw {3}" -f $a.Description,$ip,($a.IPSubnet -join ','),($a.DefaultIPGateway -join ','))
      }
      $idx++
    }
  }
  $nets = @($nets | Sort-Object -Unique)
  # COV: the interface collector declares an outcome -- an empty result is a real gap, not a silent 'complete'
  if (-not $ips.Count) { CovError "no IPv4 interface enumerated -- network picture incomplete" }
  if ($nets.Count -ge 2) {
    Jackpot ("DUAL-HOMED: $($nets.Count) network segments here -> " + ($nets -join '  '))
    Add-Lead 95 "Dual-homed host ($($nets.Count) segments: $($nets -join ', '))" "Box bridges networks -- stand up a tunnel (chisel/ligolo/ssh -D SOCKS) and pivot into the other segment, then re-run the whole methodology there. Flagless boxes are often the pivot." -CanonicalSource 'dual-homed' -Consumer 'network-topology' -Primitive 'pivot-multihomed'
  } elseif ($nets.Count -eq 1) {
    Info "Single segment ($($nets[0])) -- no obvious pivot from here."
  }
  Sub "routes toward internal ranges (extra reachable segments)"
  try {
    Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
      Where-Object { $_.DestinationPrefix -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' -and $_.DestinationPrefix -notmatch '/32$' } |
      ForEach-Object { Waldo ("route -> {0} via {1}" -f $_.DestinationPrefix,$_.NextHop) }
  } catch {
    (route print -4 2>$null) | Select-String -Pattern '(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | ForEach-Object { Note ($_.Line.Trim()) }
  }
  # v0.15 C3/C4: score a route to a NON-attached network (real prefix from IP+mask), + attack-position note
  try {
    # C3: is $ip inside CIDR $cidr, using the network's REAL prefix (no /24 assumption)?
    function script:Test-IpInCidr($ip,$cidr){ try { $p=$cidr -split '/'; $len=[int]$p[1]; $ib=[Net.IPAddress]::Parse($ip).GetAddressBytes(); $nbb=[Net.IPAddress]::Parse($p[0]).GetAddressBytes(); [Array]::Reverse($ib); [Array]::Reverse($nbb); $iv=[BitConverter]::ToUInt32($ib,0); $nv=[BitConverter]::ToUInt32($nbb,0); $mask=if($len -le 0){[uint32]0}elseif($len -ge 32){[uint32]::MaxValue}else{[uint32]([uint32]::MaxValue -shl (32-$len))}; ($iv -band $mask) -eq ($nv -band $mask) } catch { $false } }
    $attached=@()
    foreach ($a in (Get-Cim Win32_NetworkAdapterConfiguration "IPEnabled=True")) { $ipl=@($a.IPAddress); $msk=@($a.IPSubnet); for($i=0;$i -lt $ipl.Count;$i++){ if($ipl[$i] -match '^\d+\.\d+\.\d+\.\d+$'){ $n=script:Get-IpNet $ipl[$i] $msk[$i]; if($n){$attached+=$n} } } }
    $attached=@($attached | Sort-Object -Unique); $routedExtra=$false
    $rts = try { Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' -and $_.DestinationPrefix -notmatch '/(31|32)$' } } catch { @() }
    foreach ($rt in $rts) {
      # v0.34 C3: CONTAINMENT suppression (not exact equality) -- a more-specific route inside an attached network is ATTACHED.
      $rtIp = ($rt.DestinationPrefix -split '/')[0]
      $contained = ($attached -contains $rt.DestinationPrefix)
      if (-not $contained) { foreach ($aw in $attached) { if (script:Test-IpInCidr $rtIp $aw) { $contained = $true; break } } }
      if ($contained) { continue }
      $routedExtra=$true; Add-Lead 80 "Route to non-attached network: $($rt.DestinationPrefix) (via $($rt.NextHop), if $($rt.InterfaceAlias)$(if($rt.RouteMetric -ne $null){", metric $($rt.RouteMetric)"}))" "This host reaches $($rt.DestinationPrefix), NOT one of its own subnets (attached: $($attached -join ', ')) -- a pivot lead even from a single NIC.$(if($rt.RouteMetric -ne $null){" Route metric $($rt.RouteMetric) (lower = the preferred active path)."}) Tunnel from here and re-run; an unowned gateway may already forward. Source: this host / $($rt.InterfaceAlias)." -CanonicalSource (Redact-ForId "$($rt.DestinationPrefix)") -Consumer 'route-to-non-attached-network' -Primitive 'route-to-non-attached-network' }
    if ($attached.Count -ge 2 -or $routedExtra) { Note "attack-position: you hold a LAN-adjacent vantage onto the segment(s) above -- timing-sensitive (heap-groom/race) or auth-walled attacks may behave differently launched from here than across the VPN." }
    # v0.15 C3: IP forwarding = this host actively ROUTES between segments (stronger than merely multi-homed)
    $ipr = try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -ErrorAction Stop).IPEnableRouter } catch { $null }
    $fwdIf = try { @(Get-NetIPInterface -AddressFamily IPv4 -Forwarding Enabled -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notmatch '(?i)loopback' }) } catch { @() }
    if ($ipr -eq 1 -or $fwdIf.Count -gt 0) {
      # C3: forwarding is only a "router between segments" claim when a SECOND segment/route is actually observed.
      if ($attached.Count -ge 2 -or $routedExtra) {
        Jackpot "IP forwarding ENABLED + a second segment/route observed -- this host routes between segments$(if($ipr -eq 1){' (IPEnableRouter=1)'}else{" (on: $((($fwdIf | ForEach-Object InterfaceAlias) -join ', ')))"})"
        Add-Lead 84 "IP forwarding enabled + multi-segment -- host is a router between segments" "This box forwards IPv4 packets between its networks$(if($ipr -eq 1){' (IPEnableRouter=1)'}else{''}) AND a second segment/non-attached route is present, so traffic you send may already reach the far segment THROUGH it. A tunnel here is a first-class pivot; the adjacent segment may be reachable with no tunnel at all. Manual review." -CanonicalSource 'ip-forwarding-router' -Consumer 'network-topology' -Primitive 'pivot-router'
      } else {
        Note "IP forwarding enabled$(if($ipr -eq 1){' (IPEnableRouter=1)'}else{''}), but only one attached segment and no non-attached route observed -- nothing to bridge from here. Not scored as a pivot."
      }
    }
  } catch { CovError "non-attached-route / IP-forwarding correlation failed: $($_.Exception.Message)" }
  # v0.34 C3: read-only Windows FIREWALL context -- per-profile state + default inbound/outbound actions affect which local listeners are reachable and whether a reverse shell egresses. No rule changes.
  Sub "Local firewall context (read-only -- affects reachability & egress)"
  try {
    $fp = Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { "{0}={1}(in:{2},out:{3})" -f $_.Name, $(if($_.Enabled){'on'}else{'OFF'}), $_.DefaultInboundAction, $_.DefaultOutboundAction }
    Note ("Firewall profiles: " + ($fp -join '  '))
    if (@(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled }).Count -gt 0) { Note "  >> at least one profile is OFF -- local listeners on that profile are reachable; confirm which profile is active for your interface" }
  } catch {
    $fw = try { (netsh advfirewall show allprofiles state 2>$null) -join ' ' } catch { '' }
    if ($fw) { Note ("Firewall (netsh): " + ($fw -replace '\s+',' ')) } else { Note "firewall state not queryable at this privilege -- listeners likely reachable as shown; confirm egress for reverse shells" }
  }
  Sub "ARP neighbours (live hosts to hit after pivoting)"
  # C3: classify each neighbour against the ATTACHED nets (real prefix) + surface link state; an off-segment neighbour is a live host reachable only via the pivot.
  try {
    $nb = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' -and $_.State -notmatch '(?i)Unreachable|Incomplete' })
    foreach ($nbr in $nb) {
      $off = $true; foreach ($aw in $attached) { if (script:Test-IpInCidr $nbr.IPAddress $aw) { $off=$false; break } }
      $tag = if ($off) { '  <- live host on a NON-attached segment (reachable via the pivot)' } else { '' }
      Waldo "neigh $($nbr.IPAddress) [$($nbr.State)]$tag"
    }
  } catch {
    (arp -a 2>$null) | Select-String -Pattern '(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*dynamic' | ForEach-Object { Waldo ($_.Line.Trim()) }
  }
  Sub "hosts file & DNS (internal DNS often = the DC)"
  (Get-Content "$env:WINDIR\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue) | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { Note $_.Trim() }
  (Get-Cim Win32_NetworkAdapterConfiguration "IPEnabled=True").DNSServerSearchOrder | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { Note "DNS: $_" }
  # SMB signing posture -- not required => relay candidate if coercion/creds available
  $srvSign = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
  if ($srvSign -eq 0) { Jackpot "SMB signing NOT required (server) -> relay candidate"; Add-Lead 66 "SMB signing not required" "This host does not require SMB signing -- an NTLM relay candidate if you can coerce auth or have creds (labs love this). Manual review." -CanonicalSource 'smb-signing-not-required' -Consumer 'host-smb-posture' -Primitive 'posture-relay-candidate' }
  elseif ($null -ne $srvSign) { Note "SMB signing required=$srvSign (relay less useful)" }
  # LOCAL SMB shares + ACL (read-only listing -- NO lure/relay advisory)
  Sub "Local SMB shares (non-default) + who can access them"
  try {
    $hiRe = '(?i)backup|dev|deploy|script|tool|transfer|profile|home|web|www|app|sql|db|IT|help ?desk|share|data|install|software'
    Get-CimInstance Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$' } | ForEach-Object {
      $sh = $_; $hot = if ($sh.Name -match $hiRe -or $sh.Path -match $hiRe) { ' [high-signal name]' } else { '' }
      Waldo "share \\$env:COMPUTERNAME\$($sh.Name) -> $($sh.Path)$hot"
      # who is granted, and is the backing path writable by us
      try {
        $sec = Get-CimInstance -ClassName Win32_LogicalShareSecuritySetting -Filter "Name='$($sh.Name)'" -ErrorAction SilentlyContinue
        if ($sec) { $sd = $sec | Invoke-CimMethod -MethodName GetSecurityDescriptor -ErrorAction SilentlyContinue
          if ($sd -and $sd.Descriptor) { foreach($ace in $sd.Descriptor.DACL){ $tr = $ace.Trustee.Name; if ($tr -match '(?i)Everyone|Users|Authenticated|Guest') { Note "      grant: $tr (mask 0x$('{0:X}' -f $ace.AccessMask))" } } }
        }
      } catch {}
      $wp = if ($sh.Path) { Test-Writable $sh.Path } else { $null }
      if ($wp -eq $true) { Jackpot "  ^ backing path WRITABLE by you: $($sh.Path)"; Add-Lead 78 "Writable local SMB share: $($sh.Name)" "Share $($sh.Name) is backed by a path writable by you ($($sh.Path)) -- served content is under your control. Manual review (Waldo places nothing)." -CanonicalSource (Redact-ForId "$($sh.Name)") -Consumer 'writable-local-smb-share' -Primitive 'writable-local-smb-share' }
      elseif ($hot) { Add-Lead 56 "High-signal SMB share: $($sh.Name)" "Share $($sh.Name) ($($sh.Path)) has a high-value name and is exported over SMB -- inventory its contents for configs/backups/keys. Manual review." -CanonicalSource (Redact-ForId "$($sh.Name)") -Consumer 'high-signal-smb-share' -Primitive 'high-signal-smb-share' }
    }
  } catch { CovError "local SMB share enumeration failed: $($_.Exception.Message)" }
  # SNMP community strings (registry) -- read-only; community strings are cred-like
  try {
    $comm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -ErrorAction SilentlyContinue
    if ($comm) { $comm.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      Jackpot "SNMP community configured: $($_.Name)"; Add-Lead 62 "SNMP community string: $($_.Name)" "Local SNMP service has community '$($_.Name)' -- a cred-like string often reused/queryable. Note it. Manual review." -CanonicalSource (Redact-ForId "$($_.Name)") -Consumer 'snmp-community-string' -Primitive 'snmp-community-string'; Add-CredArtifact 'SNMP community string' $_.Name } }
  } catch {}
} catch { CovError "network interfaces/routes collector failed: $($_.Exception.Message)" }

# =====================================================================
#  1. USERS
# =====================================================================
}

# =====================================================================
#  AD OUTBOUND RIGHTS  --  read-only LDAP: what can YOU (+ your groups) abuse?
#  The ONE Waldo check that queries the DC over the network (enumeration-only, no writes).
# =====================================================================
if ((Want 'ad') -and ($AD -or $ADUser -or $script:DomainJoined) -and -not $Loot) {
  Head "AD outbound rights -- your abusable object control (read-only LDAP to the DC)"
  Info "Enumeration-only: reads directory ACLs, never writes. This is the one check that queries the DC."
  if ($ADUser) { Info "Running AS principal '$ADUser' (bind creds provided)." }
  else { Info "Cracked a domain user? re-run '-AD -ADUser dom\user -ADPass <pw>' to see THEIR edges -- SYSTEM/machine context MISSES user-specific edges." }
  try {
    if ($ADUser) { $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE",$ADUser,$ADPass) } else { $rootDse = [ADSI]"LDAP://RootDSE" }
    $dn = [string]$rootDse.defaultNamingContext
    if (-not $dn) { throw "no DC reachable / not domain-joined" }
    # MachineAccountQuota -- enumeration fact only (non-zero => domain users may create computer accounts)
    try {
      if ($ADUser) { $domObj = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn",$ADUser,$ADPass) } else { $domObj = [ADSI]"LDAP://$dn" }
      $maq = [int]$domObj.Properties['ms-DS-MachineAccountQuota'].Value
      if ($maq -gt 0) { Jackpot "MachineAccountQuota = $maq"; Add-Lead 60 "MachineAccountQuota = $maq (non-zero)" "Domain users may create up to $maq computer account(s). This is a directory fact -- note it and review manually (Waldo creates nothing)." -CanonicalSource 'machine-account-quota' -Consumer 'domain-policy' -Primitive 'domain-maq' }
      else { Info "MachineAccountQuota = $maq (computer-account creation restricted)" }
      # DOMAIN lockout/password policy -- authoritative source for DOMAIN accounts (attributes on the domain root).
      # Intervals are stored as negative 100-nanosecond ticks; convert to a readable duration.
      function _iv([long]$t){ if ($t -eq 0) { 'none/never' } else { $m=[math]::Round([math]::Abs($t)/600000000); if($m -ge 1440){"$([math]::Round($m/1440,1)) day(s)"}elseif($m -ge 60){"$([math]::Round($m/60,1)) hr"}else{"$m min"} } }
      $lThr = [int]$domObj.Properties['lockoutThreshold'].Value
      $lObs = _iv ([long]$domObj.Properties['lockOutObservationWindow'].Value)
      $lDur = _iv ([long]$domObj.Properties['lockoutDuration'].Value)
      $mpl  = [int]$domObj.Properties['minPwdLength'].Value
      Info "[DOMAIN policy: $($cs.Domain)] (governs ALL domain accounts -- overrides local SAM for domain logons):"
      Note "   lockout threshold=$lThr ; observation window=$lObs ; lockout duration=$lDur ; min pw length=$mpl"
      if ($lThr -eq 0) { Jackpot "DOMAIN lockout threshold = 0 (NO lockout)"; Add-Lead 55 "[DOMAIN] No account lockout (threshold=0)" "Domain policy sets lockout threshold=0 -- domain accounts DO NOT lock out. Posture fact only; Waldo does not spray (any credential testing is your manual decision; watch logging)." -CanonicalSource 'domain-lockout-policy' -Consumer 'domain-policy' -Primitive 'posture-no-lockout' }
      else { Add-Lead 50 "[DOMAIN] Lockout threshold=$lThr (window=$lObs)" "Domain accounts lock after $lThr bad attempts per $lObs window. Posture fact only -- Waldo tests nothing; lockout risk is your manual consideration." -CanonicalSource 'domain-lockout-policy' -Consumer 'domain-policy' -Primitive 'posture-lockout' }
    } catch { CovError "domain lockout/password policy (LDAP) failed: $($_.Exception.Message)" }
    # child->root forest context -> print Kerberos referral guidance (the real time sink, not missing creds)
    $forestDn = [string]$rootDse.rootDomainNamingContext
    if ($forestDn -and ($forestDn -ne $dn)) {
      Jackpot "CHILD DOMAIN: this domain ($dn) is a CHILD of forest root ($forestDn)"
      Add-Lead 82 "Child->root forest path available" "You are in a child domain -- forest-root compromise via the child krbtgt (golden/inter-realm) is on the table once you own the child. Manual review (Waldo forges no tickets)." -CanonicalSource 'child-root-forest-path' -Consumer 'ad-forest' -Primitive 'forest-escalation'
      Info "Kerberos referral notes (avoid the classic child->parent time sinks):"
      Info "  - prefer the child krbtgt AES key over NTLM/RC4; use FQDN target names (not short names)."
      Info "  - fix hosts / DNS / time to the target realm BEFORE ticketing."
      Info "  - do NOT force the parent -dc-ip with a child TGT; use -target-ip to pin transport while keeping the SPN/FQDN."
    }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($ADUser) { $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn",$ADUser,$ADPass) } else { $searcher.SearchRoot = [ADSI]"LDAP://$dn" }
    $searcher.PageSize = 200
    $searcher.ClientTimeout = [TimeSpan]::FromSeconds(20)
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
    $searcher.Filter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=domainDNS))'
    [void]$searcher.PropertiesToLoad.AddRange(@('distinguishedName','samAccountName','objectClass','ntSecurityDescriptor','servicePrincipalName','userAccountControl','adminCount','userWorkstations'))
    $mine = @{}
    if ($ADUser) {
      # resolve the target principal's SID + all (transitive) group SIDs so ACE matching reflects THEM
      $un = $ADUser -replace '^.*\\',''
      $us = New-Object System.DirectoryServices.DirectorySearcher($searcher.SearchRoot); $us.Filter = "(samAccountName=$un)"
      [void]$us.PropertiesToLoad.Add('objectSid'); $ur = $us.FindOne()
      if ($ur) {
        $de = $ur.GetDirectoryEntry(); try { $de.RefreshCache(@('tokenGroups')) } catch {}
        $sid0 = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$ur.Properties['objectsid'][0]),0)).Value; $mine[$sid0] = $true
        foreach($tg in $de.Properties['tokenGroups']){ try { $mine[(New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$tg),0)).Value] = $true } catch {} }
        Info "resolved '$ADUser' -> $($mine.Count) SIDs (self + groups)"
      } else { Info "could not resolve '$ADUser' in the directory; falling back to current token SIDs"; foreach($s in $script:MySids){ $mine[$s] = $true } }
    } else { foreach($s in $script:MySids){ $mine[$s] = $true } }
    $G_FORCEPW='00299570-246d-11d0-a768-00aa006e0529'; $G_DCS1='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $G_DCS2='1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; $G_KEYCRED='5b47d60f-6090-40b2-9f37-2a4de88f3063'
    $found = 0; $adSkipped = 0
    $spnList = @(); $flagList = @()   # #10 SPN mapping + #11 benign account flags (collected in this same pass)
    # v0.34 A10: the HELD principals -- current user + supplied -ADUser + any credential principal Waldo captured.
    # A userWorkstations restriction is only a SCORED lead for a held principal (it constrains something YOU can use);
    # for other accounts it is context only, not a scored lead.
    $heldPrincipals = @(@($env:USERNAME) + @($ADUser) + @($script:CredArtifacts | ForEach-Object { $_.Principal }) | Where-Object { $_ } | ForEach-Object { ($_ -replace '.*\\','').ToLower() } | Select-Object -Unique)
    foreach($res in $searcher.FindAll()){
     # per-object isolation -- one malformed SD/attribute must NOT abort the whole AD walk
     try {
      $sdBytes = $res.Properties['ntsecuritydescriptor'][0]
      if (-not $sdBytes) { continue }
      $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
      $sd.SetSecurityDescriptorBinaryForm([byte[]]$sdBytes)
      $tdn = [string]$res.Properties['distinguishedname'][0]
      $tname = [string]$res.Properties['samaccountname'][0]; if (-not $tname) { $tname = $tdn }
      $tclass = @($res.Properties['objectclass'])[-1]
      # #10: SPN-bearing accounts (report mapping only -- no ticket request)
      if ($res.Properties['serviceprincipalname'].Count -gt 0 -and $tclass -eq 'user') {
        foreach($spn in $res.Properties['serviceprincipalname']){ $spnList += [pscustomobject]@{ Account=$tname; Spn=[string]$spn } }
      }
      # #11: BENIGN account flags only (adminCount, pwd-never-expires). Delegation / DONT_REQ_PREAUTH deliberately NOT enumerated.
      $uac = 0; [void][int]::TryParse([string]$res.Properties['useraccountcontrol'][0],[ref]$uac)
      if ($tclass -eq 'user') {
        $fl = @()
        if ([string]$res.Properties['admincount'][0] -eq '1') { $fl += 'adminCount=1 (is/was in a protected privileged group)' }
        if ($uac -band 0x10000) { $fl += 'password never expires' }
        if ($fl.Count) { $flagList += [pscustomobject]@{ Account=$tname; Flags=($fl -join '; ') } }
        $uw = [string]$res.Properties['userworkstations'][0]
        if ($uw) {
          if ($heldPrincipals -contains $tname.ToLower()) {
            Add-Lead 58 "AD logon restriction (HELD principal $tname) -> $uw" "You HOLD/are '$tname', which is restricted (userWorkstations) to: $uw. BOTH a constraint (auth failures elsewhere are POLICY, not a bad password) AND a targeting clue (those hosts deserve evidence-backed review). Waldo does not test the credential. Manual review." -CanonicalSource (Redact-ForId "logon-restriction:$tname") -Consumer 'ad-principal' -Primitive 'logon-restriction'
          } else {
            Note "AD logon restriction: $tname -> $uw (not a held principal -- context only, not scored)"
          }
        }
      }
      foreach($ace in $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])){
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (-not $mine[$ace.IdentityReference.Value]) { continue }
        $rights = $ace.ActiveDirectoryRights.ToString(); $ot = $ace.ObjectType.ToString(); $abuse = $null
        $nullGuid = '00000000-0000-0000-0000-000000000000'
        if ($rights -match 'GenericAll') {
          $abuse = switch ($tclass) {
            'group'    { 'GenericAll on group -> add yourself as a member' }
            'computer' { 'GenericAll on computer -> RBCD (write msDS-AllowedToActOnBehalfOfOtherIdentity) or shadow creds -> impersonate/takeover (e.g. DC02$)' }
            default    { 'GenericAll -> reset password / shadow creds (AddKeyCredentialLink) / targeted kerberoast' }
          }
        }
        elseif ($rights -match 'WriteDacl') { $abuse = 'WriteDacl -> grant yourself GenericAll, then reset/shadow' }
        elseif ($rights -match 'WriteOwner') { $abuse = 'WriteOwner -> take ownership, then WriteDacl' }
        elseif ($rights -match 'WriteProperty|GenericWrite|Self') {
          if ($ot -eq $G_KEYCRED) { $abuse = 'Write msDS-KeyCredentialLink -> shadow credentials (Whisker/Certipy)' }
          elseif ($tclass -eq 'group') { $abuse = 'Write member -> add yourself to the group' }
          elseif ($tclass -eq 'computer') { $abuse = 'GenericWrite on computer -> RBCD / shadow creds -> takeover' }
          else { $abuse = 'GenericWrite -> set SPN (targeted kerberoast) / logon script' }
        }
        elseif ($rights -match 'ExtendedRight') {
          if ($ot -eq $G_FORCEPW -or $ot -eq $nullGuid) { $abuse = 'AllExtendedRights/ForceChangePassword -> reset the target password' }
          elseif ($ot -eq $G_DCS1 -or $ot -eq $G_DCS2) { $abuse = 'DCSync (GetChanges/All) -> dump domain hashes (secretsdump -just-dc)' }
        }
        if ($abuse) {
          $me = try { ([System.Security.Principal.SecurityIdentifier]$ace.IdentityReference.Value).Translate([System.Security.Principal.NTAccount]).Value } catch { $ace.IdentityReference.Value }
          Jackpot "YOU ($me) --$rights--> $tname ($tclass): $abuse"
          # on a DC/SYSTEM run these ACL edges are post-compromise noise -> demote so collection floats
          $adSc = if ($script:Elevated) { 45 } else { 96 }
          Add-Lead $adSc "AD: you can abuse $tname ($tclass)$(if($script:Elevated){' (moot -- already elevated)'})" "$me --$rights--> $tname : $abuse. Read-only LDAP finding -- confirm in BloodHound; execute manually (Waldo took no action)." -CanonicalSource (Redact-ForId "$tname") -Consumer 'ad' -Primitive 'ad'
          Add-CredArtifact 'AD outbound right' "$me --$rights--> $tname : $abuse"
          $found++
        }
      }
     } catch { $adSkipped++; continue }   # skip just this object; keep walking the directory
      if ($found -ge 40) { Note "  ...(capped at 40 outbound rights)"; break }
    }
    if ($adSkipped -gt 0) { Info "AD walk: skipped $adSkipped object(s) with unreadable/malformed security descriptors (partial data retained -- one bad object no longer hides the rest)." }
    if ($found -eq 0) { Info "No abusable outbound object-control rights found for you or your groups (this is the winPEAS-ACL false-positive class -- Waldo checks YOUR SIDs specifically)." }
    # #10: SPN-to-service map (directory facts -- Waldo requests NO tickets)
    if ($spnList.Count) {
      Sub "SPN-bearing user accounts (service->account map -- no ticket requested)"
      $spnList | Group-Object Account | ForEach-Object {
        $svc = ($_.Group | ForEach-Object { ($_.Spn -split '/')[0] } | Sort-Object -Unique) -join ', '
        Waldo "$($_.Name): $($_.Group.Count) SPN(s) [$svc]"
        $_.Group | ForEach-Object { Note "      $($_.Spn)" }
      }
      Add-Lead 52 "SPN-bearing service accounts present ($($spnList.Count) SPN(s))" "User accounts carry SPNs (service accounts) -- a directory fact linking services to accounts. Note them; any offline attack is your manual decision (Waldo requests no tickets)." -CanonicalSource 'spn-service-accounts' -Consumer 'ad-accounts' -Primitive 'kerberoast-surface'
    }
    # #11: benign account flags summary
    if ($flagList.Count) {
      Sub "Notable account attributes (benign directory facts)"
      $flagList | ForEach-Object { Waldo "$($_.Account): $($_.Flags)" }
    }
  } catch { Denied "AD check skipped: $($_.Exception.Message) (no DC reachable / not domain-joined / insufficient rights)" }
  # SYSVOL/NETLOGON GPP -- REPORT files with cpassword; do NOT decrypt (decoding = producing a credential)
  try {
    $dom = (Get-Cim Win32_ComputerSystem).Domain
    if ($dom -and $dom -ne 'WORKGROUP') {
      Sub "SYSVOL Group Policy Preferences (cpassword / scripts -- read-only)"
      $sysvol = "\\$dom\SYSVOL\$dom\Policies"
      if (Test-Path -LiteralPath $sysvol) {
        Get-ChildItem -LiteralPath $sysvol -Recurse -Include *.xml -Force -ErrorAction SilentlyContinue | ForEach-Object {
          $c = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
          if ($c -match 'cpassword="([^"]+)"') {
            Jackpot "GPP cpassword in $($_.FullName)"
            Note "      cpassword=$($Matches[1])  (Groups.xml-family -- decryptable with the MS-published AES key; Waldo does NOT decrypt)"
            Add-Lead 90 "GPP cpassword present: $($_.Name)" "SYSVOL GPP file contains a cpassword blob for a pushed local/service account. It is decryptable by design (gpp-decrypt / the public key). Waldo reports the file only -- decode and use it manually." -CanonicalSource (Redact-ForId "$($_.Name)") -Consumer 'gpp-cpassword-present' -Primitive 'gpp-cpassword-present'
            Add-CredArtifact 'GPP cpassword (SYSVOL, decode manually)' $_.FullName
          }
        }
        # logon/startup scripts often hold hardcoded paths/creds
        Get-ChildItem -LiteralPath "\\$dom\SYSVOL\$dom\scripts" -Recurse -Include *.bat,*.cmd,*.ps1,*.vbs -Force -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object {
          Waldo "NETLOGON script: $($_.FullName)"; Add-CredArtifact 'NETLOGON/logon script (review for creds/paths)' $_.FullName
        }
        # writable GPO folders under SYSVOL -> GPO-abuse relationship (kept LOW vs direct SYSTEM)
        $wgpo = 0
        Get-ChildItem -LiteralPath $sysvol -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First 60 | ForEach-Object {
          if ((Test-Writable $_.FullName) -eq $true) { $wgpo++; Jackpot "WRITABLE GPO folder: $($_.FullName)"; Add-Lead 68 "Writable GPO in SYSVOL: $($_.Name)" "You can write this GPO's SYSVOL folder -- a GPO-abuse relationship (edit -> pushes to linked OUs/computers). Verify link scope in BloodHound; score is BELOW direct local-SYSTEM primitives (GPO routes are often a fragile time-sink). Manual review, no edit made." -CanonicalSource (Redact-ForId "$($_.Name)") -Consumer 'writable-gpo-in-sysvol' -Primitive 'writable-gpo-in-sysvol' }
        }
        if ($wgpo -eq 0) { Note "No writable GPO folders (GPO-abuse route not available from here)." }
      } else { Note "SYSVOL not reachable at $sysvol (creds/connectivity) -- skipped." }
    }
  } catch {}
}

if (Want 'users') {
Head "Users -- profiles that stand out"
try {
  Get-ChildItem 'C:\Users' -Force -ErrorAction Stop | ForEach-Object {
    if (-not (Is-Standard $_.Name $Std_CUsers)) { Waldo "profile: $($_.Name)   (last write $($_.LastWriteTime))" }
  }
} catch { Denied "C:\Users not listable" }
Sub "Local accounts (enabled + privileged)"
try {
  Get-Cim Win32_UserAccount "LocalAccount=True" | ForEach-Object {
    if (-not $_.Disabled) { Waldo "$($_.Name)  (enabled, sid=$($_.SID))" } else { Note "$($_.Name) (disabled)" }
  }
} catch { CovError "local account enumeration (Win32_UserAccount) failed: $($_.Exception.Message)" }
Sub "Members of local Administrators"
$script:LocalAdmins = @()
try {
  (net localgroup Administrators 2>$null) | Where-Object { $_ -and $_ -notmatch 'command completed|Alias name|Comment|Members|^-+$' } |
    ForEach-Object {
      $t=$_.Trim()
      if($t){ Waldo $t; $script:LocalAdmins += $t.ToLower(); $script:LocalAdmins += ($t -replace '^.*\\','').ToLower() }
    }
} catch { CovError "local Administrators membership (net localgroup Administrators) failed: $($_.Exception.Message)" }
# admin-like-named local accounts -- svc/deploy/backup/operator names are often the intended path
try {
  $adminNameRe = '(?i)^(svc[-_.]|.*[-_.]svc$|backup|deploy|ansible|operator|adm[-_.]|.*[-_.]adm$|jenkins|gitlab|sql(svc|admin)?|web(admin|svc)?|helpdesk|automation|task|cron)'
  Get-Cim Win32_UserAccount "LocalAccount=True" | Where-Object { $_.Name -match $adminNameRe -and $_.Name -notmatch '\$$' } | ForEach-Object {
    $dis = if ($_.Disabled) { ' (disabled)' } else { '' }
    Waldo "admin-like local account: $($_.Name)$dis"
    if (-not $_.Disabled) { Add-Lead 50 "Admin-like local account: $($_.Name)" "Account name pattern ($($_.Name)) suggests a service/admin/deploy role -- often the intended credential target on lab boxes. Check for its creds in configs/history/vaults. Manual review." -CanonicalSource (Redact-ForId "$($_.Name)") -Consumer 'admin-like-local-account' -Primitive 'admin-like-local-account' }
  }
} catch { CovError "admin-like local account scan (Win32_UserAccount) failed: $($_.Exception.Message)" }
function Test-LocalAdmin([string]$acct){
  if (-not $acct) { return $false }
  $a = $acct.ToLower(); $s = ($a -replace '^.*\\','')
  return ($script:LocalAdmins -contains $a) -or ($script:LocalAdmins -contains $s)
}

# =====================================================================
#  2. C:\ ROOT (+ deep look into non-standard dirs)
# =====================================================================
}
if (Want 'fs') {
Head "C:\ root -- items that don't belong (custom dirs scanned deep)"
try {
  Get-ChildItem 'C:\' -Force -ErrorAction Stop | ForEach-Object {
    if (Is-Standard $_.Name $Std_RootC) { return }
    if ($_.PSIsContainer) {
      $w = Test-Writable $_.FullName
      if ($w -eq $true) { Jackpot "dir -> $($_.FullName)   [WRITABLE by you]"; Add-Lead 72 "Writable non-standard root dir: $($_.FullName)" "A custom top-level dir writable by you -- possible privesc condition if a privileged process runs content from it. Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'writable-non-standard-root-dir' -Primitive 'writable-non-standard-root-dir' }
      else { Waldo "dir -> $($_.FullName)" }
      Scan-Zone $_.FullName 2 "   |-"
    } else {
      Report-Path $_.FullName 'file'
    }
  }
} catch { Denied "C:\ not listable" }

# =====================================================================
#  3. APP / DATA ROOT ZONES
# =====================================================================
}
if (Want 'fs') {
Head "App/data root zones -- scripts, configs, backups, writable files"
foreach($z in $AppRoots){
  if (-not (Test-Path -LiteralPath $z)) { continue }
  if ($z -ieq 'C:\ProgramData') {
    # ProgramData is huge & mostly stock -> only scan non-standard top-level subdirs.
    Sub "C:\ProgramData (non-standard subdirs)"
    Get-ChildItem 'C:\ProgramData' -Force -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      if (Is-Standard $_.Name $Std_ProgramData) { return }
      Waldo "ProgramData\$($_.Name)"
      Scan-Zone $_.FullName 2 "   |-"
    }
  } else {
    Sub $z
    Scan-Zone $z 3 "   |-"
  }
}

# =====================================================================
#  3b. USER-PROFILE EXECUTABLES / SCRIPTS  -- custom local tools (admintool.exe pattern)
#      Runs BEFORE history so its binaries are flagged when history is analyzed.
# =====================================================================
}
if (Want 'fs') {
Head "User-profile executables & scripts -- custom local tools / exec primitives"
$profExt = @('*.exe','*.dll','*.ps1','*.bat','*.cmd','*.vbs','*.jar')
# skip legacy junctions (Application Data -> loop) + vendor cache/DLL noise (OneDrive/Edge/etc.)
$profNoise = '(?i)\\(Application Data|Local Settings|Temporary Internet Files|INetCache|WebCache|History|WindowsApps|Packages|node_modules|\.vs|\.nuget)\\|(?i)\\(Microsoft\\(Edge|OneDrive|Teams)|OneDrive|Google\\Chrome|Mozilla|NVIDIA|Adobe|Razer|Discord)\\'
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
  Where-Object { -not (Is-Standard $_.Name $Std_CUsers) -or $_.Name -ieq 'Administrator' } | ForEach-Object {
    $u = $_.Name; $ph = $_.FullName
    $deepRoots = @($ph,"$ph\Desktop","$ph\Documents","$ph\Downloads")
    $shallowRoots = @("$ph\AppData\Local","$ph\AppData\Roaming")   # shallow per rec (caches are huge)
    $found = @()
    foreach($r in $deepRoots){ if (Test-Path -LiteralPath $r) { $found += Get-ChildItem $r -Recurse -Depth 3 -Include $profExt -File -Force -ErrorAction SilentlyContinue } }
    foreach($r in $shallowRoots){ if (Test-Path -LiteralPath $r) { $found += Get-ChildItem $r -Depth 1 -Include $profExt -File -Force -ErrorAction SilentlyContinue } }
    $found |
      Where-Object { $_.FullName -notmatch $profNoise -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
      Sort-Object { $_.FullName.ToLower() } -Unique | ForEach-Object {
        # vendor DLL noise: only surface a .dll if its name is high-signal
        if ($_.Extension -ieq '.dll' -and $_.BaseName -notmatch '(?i)(admin|tool|svc|hijack|payload|inject|priv|backup)') { return }
        Add-FlaggedBin $_.Name
        $hi = $_.BaseName -match '(?i)(admin|tool|svc|service|run|reset|backup|shell|cmd|priv|exec|payload|dump|inject)'
        $w = Test-Writable $_.FullName
        if ($w -eq $true)     { Jackpot "profile tool ($u): $($_.FullName)   [WRITABLE]"; $sc=90 }
        elseif ($hi)          { Jackpot "profile tool ($u): $($_.FullName)   [name suggests admin/exec primitive]"; $sc=86 }
        else                  { Waldo "profile exe/script ($u): $($_.FullName)"; $sc=72 }
        Add-Lead $sc "Custom executable in user profile: $($_.FullName)" "A custom $($_.Extension) in $u's profile -- possible local exec/privilege primitive. Inspect its strings and shell history for how it's invoked (positional args often carry creds). Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'custom-executable-in-user-profile' -Primitive 'custom-executable-in-user-profile'
      }
  }

# =====================================================================
#  4. PROGRAM FILES  --  non-stock installs (writable = lead)
# =====================================================================
}
if (Want 'fs') {
Head "Program Files -- non-standard installs"
foreach($pf in @(@('C:\Program Files',$Std_ProgramFiles), @('C:\Program Files (x86)',$Std_ProgramFilesX86))){
  $dir=$pf[0]; $base=$pf[1]
  Sub $dir
  try {
    Get-ChildItem $dir -Force -Directory -ErrorAction Stop | ForEach-Object {
      if (Is-Standard $_.Name $base) { return }
      Add-AppSignal $_.Name 'installed'
      $w = Test-Writable $_.FullName
      if ($w -eq $true) {
        Jackpot "app -> $($_.FullName)   [WRITABLE by you]"
        Add-AppSignal $_.Name 'writable'
        Add-Lead 74 "Writable app dir: $($_.FullName)" "Non-stock app dir writable by you -- if a service/task/other user launches its binary, possible privesc condition. Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'writable-app-dir' -Primitive 'writable-app-dir'
        # C5: a writable app dir WITHOUT a proven privileged consumer is a CANDIDATE, not an available primitive -- do NOT register it (surfaced as a lead above only).
      } else { Waldo "app -> $($_.FullName)" }
    }
  } catch { Denied "$dir not listable" }
}

# =====================================================================
#  5. TEMP FOLDERS
# =====================================================================
}
if (Want 'fs') {
Head "Temp folders -- dropped/leftover files"
$temps = @('C:\Windows\Temp','C:\Temp','C:\tmp') + `
  (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' })
foreach($t in ($temps | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $t)) { continue }
  Sub $t
  try {
    Get-ChildItem $t -Force -File -ErrorAction Stop |
      Where-Object { $InterestingExt -contains $_.Extension.ToLower() -or $ExecExt -contains $_.Extension.ToLower() } |
      Select-Object -First 40 | ForEach-Object { Report-Path $_.FullName 'tmp' }
  } catch { Denied "$t not listable" }
}

# =====================================================================
#  6. SERVICES  --  anomalies + run-as + weak config (leads)
# =====================================================================
}
if (Want 'services') {
Head "Services -- non-standard binary/quoting/perms + run-as context"
try {
  Get-Cim Win32_Service | ForEach-Object {
    $svc = $_
    # NOTE: an optional role service (IIS/MSSQL/DHCP/DNS/WDS) is often EXACTLY the anomaly that does not belong on a
    # standard build, so Waldo does NOT subtract it from anomaly detection based on ProductType. Role is ranking CONTEXT
    # only -- annotate a role-typical service but STILL evaluate/surface it normally (no suppression, no false negative).
    if ($script:RoleStockServices.Count -and $script:RoleStockServices[("$($svc.Name)").ToLower()]) { Note "role-typical service for a $($script:BaselineRole): $($svc.Name) (still evaluated as an anomaly candidate -- not suppressed)" }
    $path = $svc.PathName
    if (-not $path) { return }
    Scan-InlineCred $path "service '$($svc.Name)' binPath"
    $exe = $path
    if ($exe -match '^\s*"([^"]+)"') { $exe = $matches[1] }
    elseif ($exe -match '^\s*([^\s]+\.exe)') { $exe = $matches[1] }
    $exe = $exe.Trim('"').Trim()

    $stockPath = $exe -match '(?i)^[A-Z]:\\Windows\\'
    $unquoted  = ($path -match '\s') -and ($path -notmatch '^\s*"') -and ($exe -match '\s')
    if ($stockPath -and -not $unquoted) { return }

    $reason = @()
    if (-not $stockPath) { $reason += 'non-System32 binary' }
    if ($unquoted) { $reason += 'UNQUOTED path w/ space' }
    if ($reason.Count -eq 0) { return }

    $runAs   = $svc.StartName
    $system  = $runAs -match '(?i)LocalSystem|NT AUTHORITY\\System|^\s*$'
    Add-AppSignal (Split-Path $exe -Leaf) 'service'; Add-FlaggedBin $exe
    $wBin = Test-Writable $exe
    $dir  = try { Split-Path $exe -Parent } catch { $null }
    $wDir = if ($dir){ Test-Writable $dir } else { $null }
    if ($wBin -eq $true -or $wDir -eq $true) { Add-AppSignal (Split-Path $exe -Leaf) 'writable' }
    $regK = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    $wReg = Test-Writable $regK
    # v0.34 A9: bounded CONFIG DISCOVERY beside a non-stock service binary (ImagePath parent) -- appsettings/.config/
    # web.config/connection-strings/.udl. Capped per service; stock C:\Windows tree excluded; NOT an ACL check.
    if ($dir -and $dir -notmatch '(?i)^[A-Z]:\\Windows\\' -and (Test-Path -LiteralPath $dir)) {
      $cfgCandidates = @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)(^appsettings.*\.json$|\.config$|^web\.config$|\.udl$|^launchSettings\.json$|^connectionStrings.*\.config$)' } |
        Select-Object -First 8)
      $cfgReported = 0; $cfgEmpty = 0
      foreach($cf in $cfgCandidates){ if (Report-ConfigPath $cf.FullName "svc-cfg($($svc.Name))") { $cfgReported++ } else { $cfgEmpty++ } }
      if ($cfgReported -eq 0 -and $cfgEmpty -gt 0) { Info "svc-cfg($($svc.Name)): $cfgEmpty config file(s) beside the binary are empty/stock templates (no connection string or secret) -- no lead." }
    }

    $msg = "$($svc.Name)  [$($svc.State)/$($svc.StartMode)]  as=$runAs  ($($reason -join ', '))  -> $exe"
    if ($wBin -eq $true -or $wDir -eq $true) {
      Jackpot "$msg   [WRITABLE binary/dir]"
      Add-Lead ($(if($system){95}else{85})) "Writable service target: $($svc.Name) -> $exe" "Service runs as $runAs and its binary/dir is writable by you -- possible privesc condition (a replaced binary would run as $runAs on restart). Manual review." -CanonicalSource (Redact-ForId $exe) -Consumer "service:$($svc.Name)" -Primitive 'writable-service-binary'
      if ($system) { Add-Primitive shell "writable service target $exe (service $($svc.Name) runs as $runAs)" }
      # v0.34 A7: DLL-search-order -- writable resolved location + CONCRETE non-stock import evidence (shared gate).
      if ($wDir -eq $true -and $wBin -ne $true -and $system) {
        $ev = Get-NonStockDllEvidence $exe
        if ($ev.Dlls.Count) {
          $dllEv = ($ev.Dlls -join ', ')
          Add-Lead 88 "DLL-search-order condition: $($svc.Name) (writable $dir + non-stock DLL evidence)" "SYSTEM service EXE is not writable, but its directory ($dir) IS, and it references NON-stock DLL(s) [$($ev.Source -join ' + ')]: $dllEv. A planted DLL matching one of those, resolved from the writable directory, loads as $runAs on start. Confirm the specific missing/relative import (Process Monitor / dumpbin /imports); Waldo plants nothing. Manual review." -CanonicalSource (Redact-ForId $dir) -Consumer "service:$($svc.Name)" -Primitive 'dll-search-order'
          Add-Primitive shell "DLL-search-order: writable $dir + non-stock import ($dllEv) for SYSTEM service $($svc.Name)"
        }
      }
      # backlog #7 (confirmed): show the EXACT write-granting ACE + read-only control context
      try {
        $tgt = if ($wBin -eq $true) { $exe } else { $dir }
        $acl = Get-Acl -LiteralPath $tgt -ErrorAction Stop
        $meNames = @("$env:USERDOMAIN\$env:USERNAME","$env:USERNAME",'BUILTIN\Users','Everyone','NT AUTHORITY\Authenticated Users','BUILTIN\Authenticated Users')
        $acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -match '(?i)Write|FullControl|Modify|TakeOwnership|ChangePermissions' } | ForEach-Object {
          $id = $_.IdentityReference.Value
          $mine = if ($meNames -contains $id -or $id -match "(?i)\\$([regex]::Escape($env:USERNAME))$") { ' <= YOU/your group' } else { '' }
          Note "      ACE: $id : $($_.FileSystemRights) $(if($_.IsInherited){'(I)'}else{'(explicit)'})$mine on $tgt"
        }
      } catch { Note "      (ACE detail unavailable: $($_.Exception.Message))" }
      $sd = try { (& sc.exe sdshow $svc.Name 2>$null) -join '' } catch { '' }
      if ($sd) { Note "      control SDDL (sc sdshow): $sd  [read-only -- RP=start WP=stop DT=reconfigure for your SID?]" }
      Note "      control context: State=$($svc.State) StartMode=$($svc.StartMode) -- restart needed for a swapped binary to run (no action taken)."
    } elseif ($wReg -eq $true) {
      Jackpot "$msg   [WRITABLE service config (registry)]"
      Add-Lead ($(if($system){90}else{80})) "Writable service config: $($svc.Name)" "The service's registry config (ImagePath) is writable by you and runs as $runAs -- possible privesc condition. Manual review." -CanonicalSource (Redact-ForId "$($svc.Name)") -Consumer 'writable-service-config' -Primitive 'writable-service-config'
      if ($system) { Add-Primitive shell "writable service registry config (ImagePath) for $($svc.Name) (runs as $runAs)" }
    } elseif ($unquoted -and $system) {
      Waldo "$msg"
      Add-Lead 60 "Unquoted service path: $($svc.Name) -> $path" "Unquoted path with spaces, runs as $runAs -- check each parent dir for write access (possible privesc condition, manual review)." -CanonicalSource (Redact-ForId "$($svc.Name)") -Consumer 'unquoted-service-path' -Primitive 'unquoted-service-path'
    } else {
      Waldo $msg
      # v0.15 A9: bounded ImagePath-ancestor scan -- a writable GRANDPARENT / missing-intermediate dir is a real plant path even when the immediate dir is not writable.
      if ($system) {
        $anc = Get-WritableAncestor $exe
        if ($anc) {
          Jackpot "   ancestor WRITABLE: $($anc.Dir)  ($($anc.Kind))"
          Add-Lead 72 "Writable ImagePath ancestor: $($svc.Name) -> $($anc.Dir)" "SYSTEM service binary ($exe) and its immediate dir are not writable, but an ancestor IS: $($anc.Dir) [$($anc.Kind)]. If you can recreate the intervening path (or the service resolves through it), the binary loads from a location you control as $runAs. Confirm the resolution order before relying on it. Manual review -- Waldo plants nothing." -CanonicalSource (Redact-ForId "$($svc.Name)") -Consumer 'writable-imagepath-ancestor' -Primitive 'writable-imagepath-ancestor'
          # C5: a writable ancestor requires recreating the resolution path -- a CANDIDATE, not a proven primitive; not registered (lead above only).
        }
      }
    }
  }
} catch { Denied "service enumeration failed" }

# =====================================================================
#  7. PROCESSES  --  running from odd locations
# =====================================================================
}
if (Want 'proc') {
Head "Processes -- running from non-standard locations"
try {
  # dedup by PATH (not name) so same-named processes from different locations aren't hidden
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $pth = $null; try { $pth = $_.Path } catch {}
    if ($pth) { [pscustomobject]@{ Name=$_.Name; Path=$pth } }
  } | Sort-Object Path -Unique | ForEach-Object {
    $path = $_.Path; $nm = $_.Name
    Add-AppSignal $nm 'process'; Add-FlaggedBin $path
    if ($path -match '(?i)^[A-Z]:\\Windows\\' ) { return }
    if ($path -match '(?i)^[A-Z]:\\Program Files') { Note "$nm -> $path"; return }
    Report-Path $path "proc:$nm"
  }
} catch { CovError "process enumeration (Get-Process) failed: $($_.Exception.Message)" }

# =====================================================================
#  8. LISTENING PORTS
# =====================================================================
}
if (Want 'proc') {
Head "Listening TCP ports -- non-standard"
try {
  $pidName = @{}
  Get-Process | ForEach-Object { $pidName[[string]$_.Id] = $_.Name }
  (netstat -ano 2>$null) | Select-String 'LISTENING' | ForEach-Object {
    $c = ($_.Line -split '\s+') | Where-Object { $_ -ne '' }
    $local = $c[1]; $procId = $c[-1]
    $port = ($local -split ':')[-1]
    $pn = 0
    if ([int]::TryParse($port,[ref]$pn)) {
      if ($Std_Ports -notcontains $pn) {
        $nm = $pidName[$procId]
        if ($nm) { Add-AppSignal $nm 'listener' }
        if (@(3306,5432,1433,1521,27017,6379,5984) -contains $pn) { $script:DbListener += "$pn ($local)" }
        # enrich with owner/binary/cmdline/writable -- context remote scans can't see
        $bind = ($local -replace ':\d+$','')
        $localOnly = $bind -match '^(127\.|::1|\[::1\])'
        $pinfo = try { Get-Cim Win32_Process "ProcessId=$procId" } catch { $null }
        $bpath = if ($pinfo) { $pinfo.ExecutablePath } else { $null }
        $cmd = if ($pinfo) { $pinfo.CommandLine } else { $null }
        $wp = if ($bpath) { Test-Writable $bpath } else { $null }
        $tag = if ($localOnly) { ' [LOCAL-ONLY listener -- internal service, reachable via pivot/portfwd]' } else { '' }
        Waldo "port $pn  ($local)  pid=$procId  $nm$tag"
        if ($bpath) { Note "      bin: $bpath$(if($wp -eq $true){'   [WRITABLE by you]'}else{''})" }
        if ($cmd -and $cmd -ne $bpath) { Note "      cmd: $(($cmd -replace '\s+',' ').Substring(0,[Math]::Min(160,$cmd.Length)))"; Scan-InlineCred $cmd "process command-line ($nm pid=$procId)" }
        if ($wp -eq $true) { Add-Lead 80 "Writable binary behind listener :$pn ($nm)" "The process serving port $pn runs from a binary writable by you ($bpath) -- possible privesc/service-swap condition. Manual review." -CanonicalSource (Redact-ForId $bpath) -Consumer "listener:$pn/$nm" -Primitive 'writable-listener-binary' }
        if ($localOnly) { Add-Lead 58 "Local-only listener :$pn ($nm)" "Service bound to loopback only -- not visible to an external scan; reachable after a foothold via port-forward/pivot. Manual review." -CanonicalSource "loopback-listener:$pn" -Consumer "process:$nm" -Primitive 'local-only-listener' }
      }
    }
  }
} catch { CovError "listening-port enumeration (netstat) failed: $($_.Exception.Message)" }

# =====================================================================
#  9. AUTOSTART  --  Run keys / Startup / Tasks, with SCRIPT-ARG extraction
# =====================================================================
}
if (Want 'autostart') {
Head "Autostart -- Run keys, Startup folders, Scheduled Tasks"

Sub "Registry Run / RunOnce keys"
$runKeys = @(
  @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','machine'),
  @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','machine'),
  @('HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run','machine'),
  @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','user'),
  @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','user')
)
foreach($rkPair in $runKeys){
  $rk=$rkPair[0]; $scope=$rkPair[1]
  try {
    $props = Get-ItemProperty -Path $rk -ErrorAction Stop
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $cmd = [string]$_.Value
      $line = "$rk\$($_.Name) = $cmd"
      Add-AppSignal $_.Name 'autorun'
      $hit = $false
      foreach($tgt in (Extract-Targets $cmd)){
        Add-AppSignal (Split-Path $tgt -Leaf) 'autorun'
        if ((Test-Path -LiteralPath $tgt) -and (Test-Writable $tgt) -eq $true){
          Jackpot "$line   [target WRITABLE: $tgt]"; $hit = $true
          Add-AppSignal (Split-Path $tgt -Leaf) 'writable'
          Add-Lead ($(if($scope -eq 'machine'){88}else{62})) "Writable autostart target: $tgt" "Referenced by $rk ($scope-wide autorun). Overwrite it -- runs when $(if($scope -eq 'machine'){'any user (incl. admins) logs on'}else{'you log on'}). Possible privesc condition. Manual review." -CanonicalSource (Redact-ForId $tgt) -Consumer "runkey:$($_.Name)" -Primitive 'writable-autostart-target'
        }
        elseif ($scope -eq 'machine' -and (Test-Path -LiteralPath $tgt)) {
          # v0.34 A7: machine-wide Run-key target file NOT writable, but its DIR is + concrete non-stock import evidence
          $tdir = try { Split-Path $tgt -Parent } catch { $null }
          if ($tdir -and (Test-Writable $tdir) -eq $true -and $tdir -notmatch '(?i)^[A-Z]:\\Windows\\') {
            $ev = Get-NonStockDllEvidence $tgt
            if ($ev.Dlls.Count) { $hit = $true; Add-Lead 86 "DLL-search-order condition: machine autostart '$($_.Name)' (writable $tdir + non-stock DLL evidence)" "$rk\$($_.Name) autostarts $tgt for ANY user on logon. The exe is not writable, but its directory ($tdir) IS, and it references NON-stock DLL(s) [$($ev.Source -join ' + ')]: $($ev.Dlls -join ', '). A planted DLL matching one of those loads from the writable directory when the autorun fires. Confirm the specific missing/relative import; Waldo plants nothing. Manual review." -CanonicalSource (Redact-ForId $tdir) -Consumer "runkey:$($_.Name)" -Primitive 'dll-search-order' }
          }
        }
      }
      if (-not $hit) { Waldo $line }
    }
  } catch {}
}

Sub "Persistence autoruns (AppInit_DLLs / IFEO / WMI subs / LSA / Winlogon hooks)"
try {
  # AppInit_DLLs -- any value here loads into every GUI process
  foreach($ai in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')){
    $p = Get-ItemProperty -Path $ai -ErrorAction SilentlyContinue
    if ($p -and $p.AppInit_DLLs -and ([string]$p.AppInit_DLLs).Trim()) {
      Jackpot "AppInit_DLLs = $($p.AppInit_DLLs)  (LoadAppInit=$($p.LoadAppInit_DLLs))"
      Add-Lead 80 "AppInit_DLLs set: $($p.AppInit_DLLs)" "A DLL loaded into every GUI process. If that DLL (or this key) is writable, it is a SYSTEM-persistence/privesc path. Manual review." -CanonicalSource (Redact-ForId "$($p.AppInit_DLLs)") -Consumer 'appinit-dlls-set' -Primitive 'appinit-dlls-set'
      foreach($t in (Extract-Targets ([string]$p.AppInit_DLLs))){ if((Test-Path -LiteralPath $t) -and (Test-Writable $t) -eq $true){ Jackpot "  ^ AppInit DLL WRITABLE: $t" } }
    }
  }
  # v2.16 A8: modern .NET execution knobs (DOTNET_STARTUP_HOOKS / COR_PROFILER) in machine/user env + registry Environment.
  try {
    $netEnvHits = @()
    foreach($scope in @('Machine','User')){
      foreach($vn in @('DOTNET_STARTUP_HOOKS','COR_PROFILER','COR_ENABLE_PROFILING','COR_PROFILER_PATH')){
        $vv = [Environment]::GetEnvironmentVariable($vn,$scope)
        if ($vv) { $netEnvHits += [pscustomobject]@{ Where="env:$scope"; Name=$vn; Val=$vv } }
      }
    }
    foreach($ek in @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment','HKCU:\Environment')){
      $ep = Get-ItemProperty -Path $ek -ErrorAction SilentlyContinue
      foreach($vn in @('DOTNET_STARTUP_HOOKS','COR_PROFILER','COR_ENABLE_PROFILING')){
        if ($ep -and $ep.$vn) { $netEnvHits += [pscustomobject]@{ Where=$ek; Name=$vn; Val=[string]$ep.$vn } }
      }
    }
    # v0.34 A8: per-service Environment (names the actual consumer service directly)
    try {
      Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        $env = (Get-ItemProperty -LiteralPath $_.PSPath -Name Environment -ErrorAction SilentlyContinue).Environment
        if ($env) {
          foreach($e in @($env)){
            if ($e -match '^(DOTNET_STARTUP_HOOKS|COR_PROFILER|COR_ENABLE_PROFILING|COR_PROFILER_PATH)=(.*)$') {
              $netEnvHits += [pscustomobject]@{ Where="service:$($_.PSChildName)"; Name=$Matches[1]; Val=$Matches[2] }
            }
          }
        }
      }
    } catch { CovError "A8 per-service Environment enumeration failed: $($_.Exception.Message)" }
    # v0.42 A8: scheduled TASK actions that set a .NET knob inline -> names the task (and its run-as) as the consumer.
    try {
      foreach($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)){
        $tpriv = ($t.Principal.RunLevel -eq 'Highest') -or ($t.Principal.UserId -match '(?i)system|administrator')
        foreach($a in @($t.Actions)){
          $cl = "$($a.Execute) $($a.Arguments)"
          if ($cl -match '(?i)(DOTNET_STARTUP_HOOKS|COR_PROFILER|COR_ENABLE_PROFILING|COR_PROFILER_PATH)\s*=\s*([^\s&|"]+)') {
            $netEnvHits += [pscustomobject]@{ Where="task:$($t.TaskName)"; Name=$Matches[1]; Val=$Matches[2]; Consumer="task '$($t.TaskName)' (as $($t.Principal.UserId))"; Privileged=[bool]$tpriv }
          }
        }
      }
    } catch { CovError "A8 scheduled-task .NET-knob enumeration failed: $($_.Exception.Message)" }
    # v0.42 A8: IIS app-pool environmentVariables in applicationHost.config -> names the app pool as the consumer.
    try {
      $ahc = "$env:WINDIR\System32\inetsrv\config\applicationHost.config"
      if (Test-Path -LiteralPath $ahc) {
        [xml]$xdoc = Get-Content -LiteralPath $ahc -Raw -ErrorAction Stop
        foreach($ap in @($xdoc.configuration.'system.applicationHost'.applicationPools.add)){
          foreach($ev in @($ap.environmentVariables.add)){
            if ($ev.name -match '(?i)^(DOTNET_STARTUP_HOOKS|COR_PROFILER|COR_ENABLE_PROFILING|COR_PROFILER_PATH)$') {
              $netEnvHits += [pscustomobject]@{ Where="apppool:$($ap.name)"; Name=$ev.name; Val=$ev.value; Consumer="IIS app pool '$($ap.name)'"; Privileged=$true }
            }
          }
        }
      }
    } catch { CovError "A8 IIS app-pool .NET-knob config parse failed: $($_.Exception.Message)" }
    # v0.42 A8: visible privileged-consumer COMMAND LINES actually running with a knob set -> directly evidenced consumer.
    try {
      foreach($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '(?i)(DOTNET_STARTUP_HOOKS|COR_PROFILER|COR_ENABLE_PROFILING)' })){
        $own = try { Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue } catch { $null }
        $u = if ($own -and $own.User) { "$($own.Domain)\$($own.User)" } else { '?' }
        if ($p.CommandLine -match '(?i)(DOTNET_STARTUP_HOOKS|COR_PROFILER|COR_ENABLE_PROFILING|COR_PROFILER_PATH)\s*=\s*([^\s&|"]+)') {
          $netEnvHits += [pscustomobject]@{ Where="process:$($p.ProcessId)"; Name=$Matches[1]; Val=$Matches[2]; Consumer="running process '$($p.Name)' (pid $($p.ProcessId), as $u)"; Privileged=[bool]($u -match '(?i)system|administrator') }
        }
      }
    } catch { CovError "A8 privileged-process command-line .NET-knob scan failed: $($_.Exception.Message)" }
    foreach($h in $netEnvHits){
      Jackpot ".NET exec knob: $($h.Name)=$($h.Val)  [$($h.Where)]"
      $tgt = if ($h.Name -eq 'DOTNET_STARTUP_HOOKS') { ($h.Val -split ';')[0] } elseif ($h.Name -eq 'COR_PROFILER_PATH') { $h.Val } else { $null }
      $w = if ($tgt -and (Test-Path -LiteralPath $tgt)) { if ((Test-Writable $tgt) -eq $true) { 'WRITABLE' } else { 'present, not writable' } } elseif ($tgt) { 'referenced path ABSENT' } else { 'n/a' }
      # v0.42 A8: correlate to the EVIDENCED consumer (task/app-pool/process name it directly) and state its privilege.
      $hasPriv = [bool]$h.PSObject.Properties['Privileged']
      $consumer = if ($h.PSObject.Properties['Consumer'] -and $h.Consumer) { $h.Consumer } else { $h.Where }
      $privNote = if ($hasPriv -and $h.Privileged) { 'The evidenced consumer runs PRIVILEGED (SYSTEM/admin/app-pool) -- a direct privesc/persistence path' }
                  elseif ($hasPriv -and -not $h.Privileged) { 'The evidenced consumer is NOT privileged -- lower impact, but still attacker-controllable code in that context' }
                  else { 'If a PRIVILEGED (SYSTEM/service/app-pool) .NET process consumes it, that is a privesc/persistence path' }
      $score = if ($hasPriv -and $h.Privileged) { 88 } else { 82 }
      Add-Lead $score ".NET execution knob set: $($h.Name) [$consumer]" "$($h.Name)=$($h.Val) in $($h.Where) -- consumer: $consumer. A .NET process launched under this loads attacker-controllable code (startup hook / profiler DLL). Referenced path: ${tgt} ($w). $privNote -- an anomaly even when the path isn't writable. Manual review." -CanonicalSource (Redact-ForId "$($h.Where):$($h.Name)") -Consumer $consumer -Primitive 'dotnet-exec-knob'
    }
  } catch { CovError ".NET execution-knob collection failed: $($_.Exception.Message)" }
  # Image File Execution Options -- a 'Debugger' value hijacks the named exe
  Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { Jackpot "IFEO Debugger on $($_.PSChildName) = $dbg"; Add-Lead 78 "IFEO debugger hijack: $($_.PSChildName)" "Image File Execution Options sets a Debugger for $($_.PSChildName) -- launching that exe runs '$dbg' instead. Classic hijack/persistence; note whether $($_.PSChildName) runs privileged. Manual review." -CanonicalSource (Redact-ForId "$($_.PSChildName)") -Consumer 'ifeo-debugger-hijack' -Primitive 'ifeo-debugger-hijack' }
  }
  # Winlogon Userinit / Shell hijack (beyond the autologon-password check)
  $wl2 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
  if ($wl2) {
    if ($wl2.Userinit -and $wl2.Userinit -notmatch '(?i)^\s*C:\\Windows\\system32\\userinit\.exe,?\s*$') { Waldo "Winlogon Userinit (non-default): $($wl2.Userinit)"; Add-Lead 74 "Non-default Winlogon Userinit" "Userinit=$($wl2.Userinit) -- extra commands run at every logon as the logging-on user. Manual review." -CanonicalSource 'winlogon-userinit' -Consumer 'winlogon' -Primitive 'autostart-hijack' }
    if ($wl2.Shell -and $wl2.Shell -notmatch '(?i)^\s*explorer\.exe\s*$') { Waldo "Winlogon Shell (non-default): $($wl2.Shell)"; Add-Lead 74 "Non-default Winlogon Shell" "Shell=$($wl2.Shell) -- runs at logon instead of/with explorer. Manual review." -CanonicalSource 'winlogon-shell' -Consumer 'winlogon' -Primitive 'autostart-hijack' }
  }
  # LSA security/authentication packages -- a rogue package loads into LSASS as SYSTEM
  $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  foreach($lp in @('Security Packages','Authentication Packages','Notification Packages')){
    $v = $lsa.$lp
    if ($v) { $vv = ($v -join ' '); if ($vv -match '(?i)[a-z]' -and $vv -notmatch '(?i)^(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|scecli|rassfm)(\s+(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|scecli|rassfm))*\s*$') { Waldo "LSA $lp (non-stock entry): $vv"; Add-Lead 72 "Non-stock LSA package: $lp" "$lp=$vv contains a non-standard module -- loads into LSASS (SYSTEM). Verify the DLL is legit/not writable. Manual review." -CanonicalSource (Redact-ForId "$lp") -Consumer 'non-stock-lsa-package' -Primitive 'non-stock-lsa-package' } } }
  # WMI permanent event subscriptions -- fileless persistence
  try {
    $consumers = Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue
    if (-not $consumers) { $consumers = Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' -ErrorAction SilentlyContinue }
    if ($consumers) { $consumers | ForEach-Object { Waldo "WMI event consumer: $($_.Name) ($($_.CimClass.CimClassName)$($_.__CLASS))"; Add-Lead 70 "WMI permanent event subscription: $($_.Name)" "A __EventConsumer exists -- WMI fileless persistence runs as SYSTEM on its trigger. Review the CommandLineTemplate/ScriptText. Manual review." -CanonicalSource (Redact-ForId "$($_.Name)") -Consumer 'wmi-permanent-event-subscription' -Primitive 'wmi-permanent-event-subscription' } }
  } catch {}
} catch { CovError "persistence-autoruns collector (AppInit/IFEO/Winlogon/LSA/WMI) failed: $($_.Exception.Message)" }

Sub "Startup folders"
$startups = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") + `
  (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
foreach($s in ($startups | Select-Object -Unique)){
  try {
    Get-ChildItem $s -Force -File -ErrorAction Stop | Where-Object { $_.Name -ne 'desktop.ini' } |
      ForEach-Object { Report-Path $_.FullName 'startup' }
  } catch {}
}

Sub "Scheduled tasks (non-Microsoft)"
try {
  $csv = schtasks /query /fo csv /v 2>$null | ConvertFrom-Csv
  $csv | Where-Object { $_.TaskName -and $_.TaskName -ne 'TaskName' -and $_.TaskName -notmatch '^\\Microsoft\\' -and $_.'HostName' } |
    Sort-Object TaskName -Unique | ForEach-Object {
      $tn = $_.TaskName; $run = $_.'Task To Run'; $asu = $_.'Run As User'
      $next = $_.'Next Run Time'; $sched = $_.'Schedule Type'
      $system  = $asu -match '(?i)SYSTEM|LocalSystem|NETWORK SERVICE|LOCAL SERVICE'
      $adminRA = Test-LocalAdmin $asu
      $priv    = $system -or $adminRA
      $ctx = "as $asu"; if($adminRA){ $ctx += ' =LOCAL ADMIN' }
      $line = "$tn  ($ctx; $sched; next $next)  -> $run"
      Scan-InlineCred $run "scheduled task '$tn' action"
      $hit = $false
      foreach($tgt in (Extract-Targets $run)){
        Add-AppSignal (Split-Path $tgt -Leaf) 'autorun'
        if (-not (Test-Path -LiteralPath $tgt)) {
          # score by context -- low-priv + writable parent = high (plant it); SYSTEM = post-compromise note
          $pdir = try { Split-Path $tgt -Parent } catch { $null }
          $pw = if ($pdir -and (Test-Path -LiteralPath $pdir)) { (Test-Writable $pdir) -eq $true } else { $false }
          if ($pw -and -not $script:Elevated) { Jackpot "   task target MISSING + parent WRITABLE: $tgt"; Add-Lead ($(if($priv){94}else{80})) "Missing task target in writable dir: $tgt (runs $ctx)" "Task '$tn' points at a non-existent file whose parent dir you can write -- create it and the next trigger runs your code $ctx. Manual review." -CanonicalSource (Redact-ForId "$tgt") -Consumer 'missing-task-target-in-writable-dir' -Primitive 'missing-task-target-in-writable-dir' }
          elseif ($script:Elevated) { Note "   task target missing: $tgt (post-compromise note -- already elevated)" }
          else { Note "   task target missing: $tgt (parent not writable/unknown -- low)" }
          continue
        }
        $wf = (Test-Writable $tgt) -eq $true
        $dir = try { Split-Path $tgt -Parent } catch { $null }
        $wd = if($dir){ (Test-Writable $dir) -eq $true } else { $false }
        # enrich -- exists/readable + first line (so the operator doesn't have to open it)
        if ($priv -and -not $NoContent) {
          try { $tf = Get-Item -LiteralPath $tgt -ErrorAction Stop; $fl = (Get-Content -LiteralPath $tgt -TotalCount 1 -ErrorAction SilentlyContinue); Note "   target: readable, $($tf.Length) bytes, first line: $([string]$fl)" } catch { Note "   target present but NOT readable at this priv" }
        }
        if ($wf -or $wd) {
          $hit = $true
          Add-AppSignal (Split-Path $tgt -Leaf) 'writable'
          $what = if($wf){"target file"}else{"target DIR ($dir)"}
          $score = if($priv){95}else{80}
          Jackpot "$line   [$what WRITABLE: $tgt]"
          Add-Lead $score "Writable task target: $tgt (runs $ctx)" "Task '$tn' executes it $ctx$(if($priv){' -- possible privesc condition'}else{''}). $(if($wf){'Target file is writable by you'}else{'Target dir is writable by you'}); next trigger ($sched) would run it $ctx. Manual review." -CanonicalSource (Redact-ForId $tgt) -Consumer "task:$tn" -Primitive $(if($wf){'writable-task-binary'}else{'writable-task-dir'})
          # v0.34 A7: DLL-search-order for a PRIVILEGED task whose DIR (not file) is writable + concrete non-stock import evidence
          if ($wd -and -not $wf -and $priv) {
            $ev = Get-NonStockDllEvidence $tgt
            if ($ev.Dlls.Count) { Add-Lead 88 "DLL-search-order condition: task '$tn' (writable $dir + non-stock DLL evidence)" "Task '$tn' runs $ctx from $tgt (not writable) but its DIR ($dir) IS, and it references NON-stock DLL(s) [$($ev.Source -join ' + ')]: $($ev.Dlls -join ', '). A planted DLL matching one of those loads as the task user on the next trigger. Confirm the specific relative/missing import; Waldo plants nothing. Manual review." -CanonicalSource (Redact-ForId $dir) -Consumer "task:$tn" -Primitive 'dll-search-order'; if($priv){ Add-Primitive shell "DLL-search-order: writable $dir + non-stock import for privileged task '$tn'" } }
          }
        }
      }
      if (-not $hit) { if($priv){ Waldo "$line   [runs privileged -- verify target/dir perms]" } else { Waldo $line } }
    }
} catch { Denied "schtasks query failed" }

# =====================================================================
#  10. PATH
# =====================================================================
}
if (Want 'proc') {
Head "PATH -- composition, ordering & hijack surface"
Info "PATH = $env:PATH"
$seen = @{}; $pos = 0; $writableEarly = $null
($env:PATH -split ';') | Where-Object { $_ } | ForEach-Object {
  $pos++
  $d = $_.Trim().TrimEnd('\')
  if ($d -eq '') { return }
  if ($seen[$d]) { Waldo "duplicate PATH entry #${pos}: $d"; return }
  $seen[$d] = $true
  if ($d -eq '.' -or $d -match '^\.') { Jackpot "relative '.' in PATH #${pos}: $d"; Add-Lead 72 "Relative entry in PATH (pos $pos): $d" "Current-dir on PATH -- a binary you drop can shadow a command a privileged process invokes. Manual review." -CanonicalSource (Redact-ForId "$pos") -Consumer 'relative-entry-in-path-pos' -Primitive 'relative-entry-in-path-pos'; return }
  if (-not (Test-Path -LiteralPath $d)) { Waldo "PATH dir #${pos} missing: $d (a writable parent lets you create it)"; return }
  $std = $d -match '(?i)^[A-Z]:\\Windows'
  $w = Test-Writable $d
  if ($w -eq $true) {
    if (-not $std -and -not $writableEarly) { $writableEarly = "${d} (pos $pos)" }
    Jackpot "WRITABLE PATH dir #${pos}: $d"
    Add-Lead 74 "Writable PATH dir (pos $pos): $d" "On PATH and writable -- plant a binary/DLL to shadow a command another user/service invokes. Earlier position wins resolution. Manual review." -CanonicalSource (Redact-ForId "$pos") -Consumer 'writable-path-dir-pos' -Primitive 'writable-path-dir-pos'
  } elseif (-not $std) { Waldo "non-standard PATH dir #${pos}: $d" }
}
if ($writableEarly) { Add-Lead 78 "Writable non-Windows dir on PATH: $writableEarly" "A writable/non-standard dir is on PATH -- if it precedes the Windows dirs, an un-pathed command call resolves to your planted binary. Cross-check un-pathed commands in services/tasks. Manual review." -CanonicalSource (Redact-ForId "$writableEarly") -Consumer 'writable-non-windows-dir-on-path' -Primitive 'writable-non-windows-dir-on-path' }

# =====================================================================
#  11. USER DATA FOLDERS
# =====================================================================
}
if (Want 'fs') {
Head "User data folders -- what you can and can't reach"
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
  Where-Object { -not (Is-Standard $_.Name $Std_CUsers) -or $_.Name -ieq 'Administrator' } |
  ForEach-Object {
    $u = $_.Name
    foreach($sub in @('Desktop','Documents','Downloads')){
      $p = Join-Path $_.FullName $sub
      if (-not (Test-Path -LiteralPath $p)) { continue }
      try {
        $items = Get-ChildItem $p -Force -ErrorAction Stop | Where-Object { $_.Name -ne 'desktop.ini' }
        if ($items) {
          Info "$u\$sub  ($($items.Count) item(s)):"
          $items | Select-Object -First 20 | ForEach-Object {
            if (-not $_.PSIsContainer -and $InterestingExt -contains $_.Extension.ToLower()) { Report-Path $_.FullName '' }
            else { Note "   $($_.Name)" }
          }
        }
      } catch { Denied "$u\$sub  [access denied]" }
    }
  }

# =====================================================================
#  12. SECRETS & HISTORY  --  where creds actually hide
# =====================================================================
}
if (Want 'creds') {
Head "Secrets & history -- creds, tokens, saved sessions"
Sub "Saved credentials (cmdkey / Credential Manager)"
$ck = (cmdkey /list 2>$null) | Select-String 'Target:|User:'
$ck | ForEach-Object { Waldo $_.Line.Trim() }
if ($ck) { Add-CredArtifact 'Windows Credential Manager entry' 'cmdkey /list (extractable via runas /savecred or DPAPI tooling)' }

Sub "Per-user history & credential files"
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
  $h = $_.FullName; $u = $_.Name
  # shell/PS history -- print content + catch flagged-tool usage & positional creds (the .153 miss)
  foreach($hf in @("$h\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt","$h\.bash_history","$h\.zsh_history")){
    Analyze-History $hf $u
  }
  $cands = @(
    "$h\.ssh\id_rsa","$h\.ssh\id_ed25519","$h\.ssh\config",
    "$h\.aws\credentials","$h\.azure\accessTokens.json",
    "$h\AppData\Roaming\Microsoft\Credentials",
    "$h\Documents\Default.rdp","$h\Desktop\Default.rdp",
    "$h\.git-credentials","$h\AppData\Local\Microsoft\Vault"
  )
  foreach($c in $cands){
    if (Test-Path -LiteralPath $c) {
      Report-Path $c "$u"
      if     ($c -match 'id_rsa|id_ed25519')        { Add-CredArtifact 'SSH private key' $c }
      elseif ($c -match '\\(Credentials|Vault)$')   { Add-CredArtifact "DPAPI Credential Manager / Vault ($u -- needs masterkey/mimikatz)" $c }
      elseif ($c -match 'git-credentials|\.rdp')    { Add-CredArtifact 'saved credential/session' $c }
    }
  }
  # password-vault / crackable cred stores (single recursive walk, filtered -- fast)
  $vaultRe = '\.(kdbx|kdb|psafe3|opvault|agilekeychain|walletx|rdp|rdg|ppk|pem|pfx|p12|env)$|(^|\\)(logins\.json|key4\.db|signons\.sqlite|confCons\.xml|Login Data)$'
  $depth = if ($script:HasDepth) { 3 } else { 99 }
  $walk = if ($script:HasDepth) { Get-ChildItem $h -Recurse -Depth $depth -File -Force -ErrorAction SilentlyContinue }
          else                  { Get-ChildItem $h -Recurse -File -Force -ErrorAction SilentlyContinue }
  $walk | Where-Object { $_.Name -match $vaultRe } | Select-Object -First 8 | ForEach-Object {
    Report-Path $_.FullName "$u"
    $e = $_.Extension.ToLower()
    $ct = if($e -in '.rdp','.rdg'){'saved RDP session (DPAPI)'} elseif($e -in '.ppk','.pem','.pfx','.p12'){'private key / cert'} elseif($_.Name -in 'logins.json','key4.db','signons.sqlite'){'browser saved logins'} elseif($_.Name -eq 'confCons.xml'){'mRemoteNG saved sessions'} else {'password vault'}
    Add-Lead 80 "Credential store: $($_.FullName)" "$ct -- exfil & crack/decrypt (no spraying done). Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'credential-store' -Primitive 'credential-store'
    Add-CredArtifact $ct $_.FullName
  }
}
Sub "Saved-session software creds (PuTTY / WinSCP / FileZilla / mRemoteNG)"
# PuTTY sessions (HostName/UserName + any stored proxy creds) in HKCU per user hive
try {
  Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue | ForEach-Object {
    $s = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    Waldo "PuTTY session '$($_.PSChildName)': $($s.HostName)  user=$($s.UserName)  keyfile=$($s.PublicKeyFile)"
    Add-CredArtifact 'PuTTY saved session' "$($_.PSChildName) -> $($s.HostName)"
    if ($s.ProxyPassword) { Jackpot "  PuTTY ProxyPassword stored (cleartext) for $($_.PSChildName)"; Add-Lead 82 "PuTTY stored proxy password: $($_.PSChildName)" "PuTTY saved a cleartext proxy password in the registry. Read HKCU\...\PuTTY\Sessions. Manual review." -CanonicalSource (Redact-ForId "$($_.PSChildName)") -Consumer 'putty-stored-proxy-password' -Primitive 'putty-stored-proxy-password' }
  }
} catch { CovError "PuTTY saved-session enumeration failed: $($_.Exception.Message)" }
# PuTTY recursive VALUE grep -- catches cleartext plink/-pw commands stored in ARBITRARY values
# (not just HostName/UserName), e.g. a saved 'plink -pw <pass> user@host' string.
try {
  Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if (-not $props) { return }
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $val = [string]$_.Value
      if ($val -match '(?i)(-pw\s|plink|passw|\.ppk|sshpass)') {
        $show = $val.Substring(0,[Math]::Min(120,$val.Length))
        Jackpot "PuTTY value [$($_.Name)]: $show"
        Add-Lead 86 "PuTTY registry value holds a plink/-pw command: $($_.Name)" "A PuTTY registry value contains a plink/-pw/password string (often a cleartext password + target host). Read HKCU\Software\SimonTatham\PuTTY. Manual review." -CanonicalSource (Redact-ForId "$($_.Name)") -Consumer 'putty-registry-value-holds-a-plink-pw-command' -Primitive 'putty-registry-value-holds-a-plink-pw-command'
        Add-CredArtifact 'PuTTY value (cleartext plink/-pw likely)' "$($_.Name): $show"
      }
    }
  }
} catch { CovError "PuTTY registry value scan (plink/-pw) failed: $($_.Exception.Message)" }
# WinSCP sessions (Password field is obfuscated, not encrypted -- crackable offline)
try {
  Get-ChildItem 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' -ErrorAction SilentlyContinue | ForEach-Object {
    $s = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    Waldo "WinSCP session '$($_.PSChildName)': $($s.HostName)  user=$($s.UserName)"
    if ($s.Password) { Jackpot "  WinSCP stored Password (recoverable) for $($_.PSChildName)"; Add-Lead 84 "WinSCP stored session password: $($_.PSChildName)" "WinSCP stores the session password obfuscated (not encrypted) -- recover offline (e.g. winscppasswd / Get-WinSCPPassword). Manual review." -CanonicalSource (Redact-ForId "$($_.PSChildName)") -Consumer 'winscp-stored-session-password' -Primitive 'winscp-stored-session-password' ; Add-CredArtifact 'WinSCP session password (recoverable)' "$($_.PSChildName) -> $($s.HostName)" }
    else { Add-CredArtifact 'WinSCP saved session' "$($_.PSChildName) -> $($s.HostName)" }
  }
} catch { CovError "WinSCP saved-session enumeration failed: $($_.Exception.Message)" }
# FileZilla saved sites (Pass base64 in XML)
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
  foreach($fz in @("$($_.FullName)\AppData\Roaming\FileZilla\sitemanager.xml","$($_.FullName)\AppData\Roaming\FileZilla\recentservers.xml")){
    if (Test-Path -LiteralPath $fz) { Jackpot "FileZilla saved sites: $fz"; Add-Lead 82 "FileZilla saved credentials: $fz" "FileZilla stores host/user and base64 (not encrypted) passwords -- decode offline. Manual review." -CanonicalSource (Redact-ForId "$fz") -Consumer 'filezilla-saved-credentials' -Primitive 'filezilla-saved-credentials'; Add-CredArtifact 'FileZilla saved password (base64)' $fz }
  }
}
Sub "Provisioning / guest-agent / setup logs (creds & flags often leak here)"
$provLogs = @(
  'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init.log',
  'C:\Windows\Temp\cloudbase-init.log','C:\Windows\debug\NetSetup.log',
  'C:\Windows\Panther\setupact.log','C:\Windows\Panther\UnattendGC\setupact.log')
# Cloudbase-Init config + local scripts (not always caught by generic app-root scan) -- these hold creds/logic
$provLogs += (Get-ChildItem 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf','C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts' -Recurse -Depth 2 -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$provLogs += (Get-ChildItem 'C:\Windows\Temp','C:\Windows\System32\GroupPolicy' -Recurse -Depth 2 -Include 'cloudbase*.log','*qemu*.log','*guest*.log' -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach($lg in ($provLogs | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $lg)) { continue }
  $m = Select-String -LiteralPath $lg -Pattern 'password|passwd|pwd|cred|secret|sshpass|plink|proof\.txt|local\.txt|Administrator|username' -ErrorAction SilentlyContinue | Select-Object -First 6
  # separate config FLAGS (context) from actual credential VALUES.
  $realHits = @($m | Where-Object { $_.Line -notmatch '(?i)(inject_user_password|inject_metadata_password|.*password\s*[:=]\s*(true|false|yes|no|0|1)\s*$|_enabled|metadata_services|plugins)' })
  $flagHits = @($m | Where-Object { $_.Line -match '(?i)(inject_user_password|inject_metadata_password)\s*[:=]\s*true' })
  if ($realHits.Count -gt 0) { Jackpot "provisioning file with cred/flag values: $lg"; $realHits | ForEach-Object { Say ("         > $($_.Line.Trim())") 'Red' }; Add-Lead 80 "Provisioning log/config leaks creds/flag: $lg" "Guest-agent/cloud-init/setup file contains credential- or flag-shaped VALUES. Manual review." -CanonicalSource (Redact-ForId "$lg") -Consumer 'provisioning-log-config-leaks-creds-flag' -Primitive 'provisioning-log-config-leaks-creds-flag'; Add-CredArtifact 'provisioning log/config secret' $lg }
  elseif ($flagHits.Count -gt 0) { Waldo "provisioning: password INJECTION enabled (context, no value here): $lg"; Add-Lead 62 "Cloudbase password injection enabled: $lg" "inject_user_password=true is a flag, NOT a password. The value lives elsewhere -> check SECURITY/LSA secrets, setup logs, unattend.xml, and the cloudbase-init log. Manual review." -CanonicalSource (Redact-ForId "$lg") -Consumer 'cloudbase-password-injection-enabled' -Primitive 'cloudbase-password-injection-enabled' }
  else { Note "provisioning file (no obvious hits): $lg" }
}
# provisioning realm may differ from the LIVE realm -> Kerberos targeting trap
try {
  $nsRealm = (Select-String -LiteralPath "$env:WINDIR\debug\NetSetup.LOG" -Pattern 'DnsDomainName|domain\s*[:=]\s*\S+' -ErrorAction SilentlyContinue | Select-Object -First 1)
  $liveDns = ((Get-Cim Win32_ComputerSystem).Domain)
  if ($nsRealm -and $liveDns -and ($nsRealm.Line -notmatch [regex]::Escape($liveDns))) {
    Waldo "provisioning realm (NetSetup) may differ from live domain '$liveDns'"
    Add-Lead 60 "Provisioning realm != live realm" "NetSetup/provisioning references a realm that differs from the live domain ($liveDns). Confirm the LIVE realm (nltest/echo %USERDNSDOMAIN%) before Kerberos ticketing -- wrong realm/SPN is a classic time sink. Manual review." -CanonicalSource 'provisioning-realm-mismatch' -Consumer 'provisioning' -Primitive 'stale-realm'
  }
} catch {}
Sub "Sysprep / unattend answer files (autounattend, Panther)"
$unattend = @('C:\unattend.xml','C:\autounattend.xml','C:\sysprep.inf','C:\sysprep.xml',
  "$env:WINDIR\Panther\Unattend.xml","$env:WINDIR\Panther\Unattended.xml",
  "$env:WINDIR\System32\Sysprep\unattend.xml","$env:WINDIR\System32\Sysprep\Panther\unattend.xml")
$unattend += (Get-ChildItem "$env:WINDIR\Panther" -Recurse -Depth 2 -Include 'Unattend*.xml','autounattend.xml' -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach($ua in ($unattend | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $ua)) { continue }
  Report-Path $ua 'unattend'
  if (Select-String -LiteralPath $ua -Pattern 'Password|AdministratorPassword|<Value>' -ErrorAction SilentlyContinue) { Add-Lead 80 "Answer file may hold a password: $ua" "unattend/sysprep answer files often embed a base64 AdministratorPassword. Decode it and preserve as an exact pair with origin scope; any use is your manual decision. Waldo does not test/reuse." -CanonicalSource (Redact-ForId "$ua") -Consumer 'answer-file-may-hold-a-password' -Primitive 'answer-file-may-hold-a-password'; Add-CredArtifact 'unattend AdministratorPassword' $ua }
}
Sub "web/app config files (connection strings & CMS creds)"
$webCfgNames = @('web.config','appsettings*.json','local.settings.json','*.udl','.htaccess',
  'launchSettings.json',
  'config.php','configuration.php','database.php','wp-config.php','settings.php','connectionStrings*.config')
$webZones = @('C:\inetpub','C:\wwwroot','C:\www','C:\xampp\htdocs','C:\wamp\www','C:\wamp64\www','C:\laragon\www','C:\transfer') +
  (Get-ChildItem 'C:\' -Directory -Filter 'Apache*' -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'htdocs' })
foreach($z in ($webZones | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $z)) { continue }
  Get-ChildItem $z -Recurse -Include $webCfgNames -File -Force -ErrorAction SilentlyContinue |
    Select-Object -First 20 | ForEach-Object { Report-Path $_.FullName 'webcfg' }
}
# v0.34 A9: general application-install-root config discovery. Bounded walk of NON-stock Program Files app roots for
# cred-bearing config, per-app capped, stock trees excluded, empty/stock templates suppressed (empty-template negative).
Sub "Application-install-root config discovery (Program Files -- non-stock app roots, empty-template negatives)"
$piRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
$stockAppRe = '(?i)^(Windows.*|Microsoft.*|Common Files|Internet Explorer|WindowsApps|ModifiableWindowsApps|dotnet|MSBuild|IIS.*|Reference Assemblies|Uninstall Information|WindowsPowerShell|VMware|VMware Tools|Windows Defender.*)$'
$piCfgNames = @('appsettings*.json','*.config','web.config','*.udl','connectionStrings*.config','launchSettings.json')
$piCfgReported = 0; $piCfgEmpty = 0; $piApps = 0
# v0.41 COV: the whole recursive app-root enumeration runs under a per-collector DEADLINE; classification (content
# read / empty-template gate) stays in the parent. On timeout the collector is honestly PARTIAL, not silently empty.
$cands = Invoke-Bounded -What 'app-root config discovery' -ArgumentList @($piRoots,$stockAppRe,$piCfgNames,[bool]$script:HasDepth) -Work {
  param($roots,$stockRe,$cfgNames,$hasDepth)
  $apps=0; $out=@()
  foreach($pr in $roots){
    foreach($app in @(Get-ChildItem -LiteralPath $pr -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch $stockRe } | Select-Object -First 40)){
      $apps++
      $found = if ($hasDepth) { @(Get-ChildItem -LiteralPath $app.FullName -Recurse -Depth 3 -Include $cfgNames -File -Force -ErrorAction SilentlyContinue | Select-Object -First 6) }
               else { @(Get-ChildItem -LiteralPath $app.FullName -Recurse -Include $cfgNames -File -Force -ErrorAction SilentlyContinue | Select-Object -First 6) }
      foreach($cf in $found){ $out += [pscustomobject]@{ path=$cf.FullName; app=$app.Name } }
    }
  }
  [pscustomobject]@{ apps=$apps; items=$out }
}
if ($null -eq $cands) {
  Info "App-root config discovery: TIMED_OUT at $($script:WaldoDeadline)s -- partial (raise WALDO_DEADLINE or review Program Files manually)."
} else {
  $rec = @($cands) | Select-Object -Last 1
  $piApps = [int]$rec.apps
  foreach($it in @($rec.items)){ if (Report-ConfigPath $it.path "app-cfg($($it.app))") { $piCfgReported++ } else { $piCfgEmpty++ } }
  Info "App-root config discovery: scanned $piApps non-stock app root(s); surfaced $piCfgReported cred-bearing config(s), suppressed $piCfgEmpty empty/stock template(s) (per-app cap 6, depth 3, C:\Windows + stock apps excluded)."
}
# v0.15 A9: MSDeploy publish profiles -- DPAPI-aware. .pubxml.user stores <Password>/<UserPWD> as a DPAPI blob
# decryptable ONLY as the owning developer profile; .pubxml often holds a plaintext deploy credential.
Sub "MSDeploy publish profiles (.pubxml/.pubxml.user -- deploy creds, DPAPI-aware)"
$pubxmls = @()
# Bounded roots -- publish profiles live in project dirs (\Properties\PublishProfiles\). Target likely dev roots at
# shallow depth instead of recursing all of C:\Users (keeps Waldo a fast scalpel).
$pubRoots = @($webZones) + @('C:\Source','C:\src','C:\projects','C:\inetpub','C:\wwwroot') +
  (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
    ForEach-Object { $u=$_.FullName; @('source','repos','Documents','Desktop','Projects') | ForEach-Object { Join-Path $u $_ } })
foreach($z in ($pubRoots | Select-Object -Unique)){
  if (Test-Path -LiteralPath $z){ $pubxmls += (Get-ChildItem $z -Recurse -Depth 4 -Include '*.pubxml','*.pubxml.user' -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
}
foreach($pf in ($pubxmls | Select-Object -Unique | Select-Object -First 20)){
  if (-not (Test-Path -LiteralPath $pf)) { continue }
  $txt = try { Get-Content -LiteralPath $pf -Raw -ErrorAction Stop } catch { '' }
  if ($txt -match '(?i)<(Password|UserPWD)>\s*[A-Za-z0-9+/]{40,}={0,2}\s*</') {
    Jackpot "publish profile (DPAPI-encrypted password): $pf"
    Add-Lead 78 "Publish profile with DPAPI-encrypted password: $pf" "A .pubxml(.user) MSDeploy profile stores <Password>/<UserPWD> as a DPAPI blob encrypted under the OWNING developer profile -- decryptable only AS that user (or with their masterkey). If you can execute as that user, it decrypts to a deploy/service credential. Preserve the file and note the owning profile. Manual review -- Waldo does not decrypt." -CanonicalSource (Redact-ForId "$pf") -Consumer 'publish-profile-with-dpapi-encrypted-password' -Primitive 'publish-profile-with-dpapi-encrypted-password'
    Add-CredArtifact 'MSDeploy publish profile (DPAPI-encrypted deploy password)' $pf
  } elseif ($txt -match '(?i)<(Password|UserPWD)>[^<]{1,80}</') {
    Jackpot "publish profile (PLAINTEXT password): $pf"
    Add-Lead 82 "Publish profile with plaintext password: $pf" "A .pubxml MSDeploy profile stores a cleartext <Password>/<UserPWD> deploy credential. Preserve the EXACT principal/secret pair with this origin. Manual review -- Waldo does not test it." -CanonicalSource (Redact-ForId "$pf") -Consumer 'publish-profile-with-plaintext-password' -Primitive 'publish-profile-with-plaintext-password'
    Add-CredArtifact 'MSDeploy publish profile (plaintext deploy password)' $pf
  } else {
    Report-Path $pf 'pubxml'
  }
}
Sub "IIS applicationHost.config (live + history -- app-pool identities, encrypted secrets)"
$iisCfgs = @("$env:WINDIR\System32\inetsrv\config\applicationHost.config")
$iisCfgs += (Get-ChildItem 'C:\inetpub\history' -Recurse -Depth 3 -Filter 'applicationHost.config' -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach($ic in ($iisCfgs | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $ic)) { continue }
  Report-Path $ic 'iis'
  Add-Lead 78 "IIS applicationHost.config: $ic" "Holds app-pool identities and (often) machineKey / encrypted connection strings. History copies survive config changes. Decrypt with 'appcmd list apppool /config' or aspnet_regiis. Manual review." -CanonicalSource (Redact-ForId "$ic") -Consumer 'iis-applicationhost-config' -Primitive 'iis-applicationhost-config'
  Add-CredArtifact 'IIS applicationHost.config (app-pool creds)' $ic
}
Sub "Writable webroots (served web dir you can write to)"
$webroots = @('C:\inetpub\wwwroot','C:\xampp\htdocs','C:\wamp\www','C:\wamp64\www','C:\laragon\www','C:\transfer','C:\www','C:\wwwroot')
$webroots += (Get-ChildItem 'C:\' -Directory -Filter 'Apache*' -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'htdocs' })
$webroots += (Get-ChildItem 'C:\inetpub' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$customTop = @(Get-ChildItem 'C:\' -Directory -Force -ErrorAction SilentlyContinue |
  Where-Object { -not (Is-Standard $_.Name $Std_RootC) -and $_.FullName -notmatch '(?i)^C:\\(Windows|Users|Program Files|Program Files \(x86\)|ProgramData)\\?$' } |
  Select-Object -First 25)
foreach($ct in $customTop){
  $webroots += Get-ChildItem -LiteralPath $ct.FullName -Recurse -Depth 3 -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '(?i)^(htdocs|www|wwwroot|webroot|public_html|public|html|cmsdocs|uploads?|files|images|static)$' } |
    Select-Object -First 12 | ForEach-Object { $_.FullName }
}
foreach($wr in ($webroots | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $wr)) { continue }
  if ((Test-Writable $wr) -eq $true) {
    Jackpot "WRITABLE webroot: $wr"
    Add-Lead 88 "Writable webroot: $wr" "A served web directory is writable by you -- possible code-execution condition (writable web content would run as the web service identity). Manual review." -CanonicalSource (Redact-ForId "$wr") -Consumer 'writable-webroot' -Primitive 'writable-webroot'
  } else { Note "webroot (not writable): $wr" }
}
Sub "Web-served interesting files (scripts, schemas, notes, staged loot)"
# Exam/lab pattern: directory listings or app routes expose deeper served files (simulate.ps1,
# schema.sql, notes, staged hives) that are not necessarily named like ordinary web configs.
$servedNames = @('*.ps1','*.bat','*.cmd','*.vbs','*.sql','*.bak','*.old','*.save','*.hiv','*.hive',
  'SAM','SYSTEM','SECURITY','NTDS.dit','*.log','*.txt','*.md','*.csv','*.env','*.ini','*.conf','*.cfg',
  '*.php','*.inc','*.config','*.json','*.yml','*.yaml','*.zip','*.7z','*.rar')
$servedSeen = @{}
foreach($wr in ($webroots | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $wr)) { continue }
  $reported = 0
  Get-ChildItem -LiteralPath $wr -Recurse -Depth 5 -Include $servedNames -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 0 -and $_.Length -lt 20MB } |
    Select-Object -First 80 | ForEach-Object {
      $k = $_.FullName.ToLower()
      if ($servedSeen[$k]) { return }
      $servedSeen[$k] = $true; $reported++
      $hot = $_.Name -match '(?i)(simulate|schema|credential|creds|password|secret|backup|dump|hive|sam|system|security|ntds|local|proof|admin|config|database|users?)'
      if ($hot) {
        Jackpot "web-served high-signal file: $($_.FullName)"
        Add-Lead 82 "Web-served high-signal file: $($_.FullName)" "A file under a served web/app directory has a credential/schema/loot/objective-shaped name. Directory listings or app routes may expose it remotely; read it locally first and preserve source provenance. Manual review -- Waldo does not download or request it over HTTP." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'web-served-high-signal-file' -Primitive 'web-served-artifact'
        Add-CredArtifact 'web-served high-signal artifact' $_.FullName
      } else {
        Waldo "web-served file: $($_.FullName)"
      }
      if (-not $NoContent) { [void](Peek-Secrets $_.FullName) }
      if ((Test-Writable $_.DirectoryName) -eq $true) {
        Add-Lead 76 "Writable served subdirectory: $($_.DirectoryName)" "A web-served subdirectory containing interesting files is writable by you. This is a write-to-served-content condition; Waldo writes nothing. Manual review." -CanonicalSource (Redact-ForId "$($_.DirectoryName)") -Consumer 'writable-served-subdirectory' -Primitive 'writable-served-subdirectory'
      }
    }
  if ($reported -ge 80) { Info "web-served artifact sweep capped at 80 files under $wr -- coverage is partial for that root." }
}
Sub "Framework / CMS fingerprint (name the app so you know which config holds creds)"
# identify the stack by signature file -> points you at the right cred/config
$cmsSigs = @(
  @('wp-config.php','WordPress (creds in wp-config.php DB_USER/DB_PASSWORD)'),
  @('configuration.php','Joomla (creds in configuration.php $user/$password)'),
  @('sites\default\settings.php','Drupal (creds in settings.php $databases)'),
  @('artisan','Laravel (creds in .env DB_*/APP_KEY)'),
  @('manage.py','Django (creds in settings.py DATABASES / SECRET_KEY)'),
  @('config\database.yml','Rails (creds in config/database.yml)'),
  @('web.config','ASP.NET (connectionStrings / machineKey in web.config)'),
  @('package.json','Node/Express (check .env / config for DB + secrets)'),
  @('WEB-INF\web.xml','Java/Tomcat app (check context.xml / properties for DB creds)') )
foreach($wr in ($webroots | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $wr)) { continue }
  foreach($sig in $cmsSigs){
    $hit = Get-ChildItem -LiteralPath $wr -Recurse -Depth 3 -Filter (Split-Path $sig[0] -Leaf) -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match [regex]::Escape($sig[0]) } | Select-Object -First 1
    if ($hit) { Waldo "$($sig[1]) -> $($hit.FullName)"; Add-Lead 64 "Web app identified: $($sig[1])" "Found $($hit.Name) under $wr. $($sig[1]). Read that config for DB creds/keys. Manual review." -CanonicalSource (Redact-ForId "$($sig[1])") -Consumer 'web-app-identified' -Primitive 'web-app-identified'; Add-CredArtifact 'web app config (framework creds)' $hit.FullName; break }
  }
}
Sub "Web stack execution identity (webshell/upload = that account)"
# When Apache/PHP runs as SYSTEM, a webshell/upload primitive is SYSTEM -- no local privesc needed.
$webSystem = $false
try {
  Get-Cim Win32_Service | Where-Object { $_.PathName -match '(?i)apache|xampp|httpd|tomcat|catalina|nginx|php-cgi' } | ForEach-Object {
    if ($_.StartName -match '(?i)LocalSystem|NT AUTHORITY\\System|^\s*$') { $webSystem = $true; Jackpot "web service '$($_.Name)' runs as SYSTEM -> $($_.PathName)" } else { Waldo "web service '$($_.Name)' as $($_.StartName)" }
  }
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)^(httpd|apache|php|php-cgi|w3wp|nginx|tomcat)' } | ForEach-Object {
    $o = try { ($_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction Stop).User } catch { $null }
    if ($o -match '(?i)SYSTEM') { $webSystem = $true; Jackpot "web process $($_.Name) (pid $($_.ProcessId)) runs as SYSTEM" }
  }
} catch { CovError "web-stack execution-identity detection failed -- SYSTEM web-stack correlation may be missed: $($_.Exception.Message)" }
if ($webSystem) { Add-Lead 90 "Web stack executes as SYSTEM" "Apache/PHP/IIS/Tomcat runs as SYSTEM here -- ANY webshell / upload / sync-into-webroot primitive is SYSTEM-level, no local privesc needed. Manual review." -CanonicalSource 'web-stack-system' -Consumer 'web-service' -Primitive 'privesc-webshell-system' }

Sub "Web-app source triage (DB / object-storage / upload-sync wiring)"
$srcRoots = @('C:\xampp\htdocs','C:\inetpub\wwwroot','C:\wamp\www','C:\wamp64\www','C:\laragon\www','C:\www','C:\wwwroot','C:\transfer') + (Get-ChildItem 'C:\' -Directory -Filter 'Apache*' -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'htdocs' })
$appWireRe = 'Aws\\S3\\S3Client|S3Client|use_path_style_endpoint|[''"](endpoint|bucket|region)[''"]|->endpoint|SaveAs|move_uploaded_file|file_put_contents|new mysqli|PDO\(|mysql_connect|AKIA[0-9A-Z]{16}|aws_secret|secret[_-]?key|access[_-]?key'
foreach($sr in ($srcRoots | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $sr)) { continue }
  Get-ChildItem $sr -Recurse -Depth 4 -Include '*.php','*.inc','*.py','*.rb','*.js','*.config','*.env','*.ini' -File -Force -ErrorAction SilentlyContinue | Select-Object -First 60 | ForEach-Object {
    $h = Select-String -LiteralPath $_.FullName -Pattern $appWireRe -ErrorAction SilentlyContinue | Select-Object -First 4
    if ($h) {
      Jackpot "app source wiring: $($_.FullName)"
      $h | ForEach-Object { Say ("         > $($_.Line.Trim())") 'Red' }
      Add-Lead 84 "App source reveals backend wiring: $($_.FullName)" "Web-app source references DB / object-storage / upload-sync / hardcoded keys -- read it for endpoint/bucket/creds and object-name->webroot writes. Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'app-source-reveals-backend-wiring' -Primitive 'app-source-reveals-backend-wiring'
      Add-CredArtifact 'app source (DB/S3/keys wiring)' $_.FullName
    }
  }
}

Sub "App DB credential-store hint (source-based -- Waldo does NOT query the DB)"
# local app DB is a FIRST-CLASS credential lead
# Remote DB login may fail while the local DB stays readable -- prefer local DB data/config over remote guessing.
$dbData = @()
foreach($dd in @('C:\xampp\mysql\data','C:\ProgramData\MySQL\MySQL Server*\Data','C:\ProgramData\MariaDB\*\data','C:\Program Files\MySQL\MySQL Server*\Data','C:\Program Files\MariaDB*\data')){
  Get-ChildItem $dd -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(mysql|performance_schema|sys|information_schema|phpmyadmin|test)$' } | ForEach-Object { $dbData += $_ }
}
if ((Test-Path 'C:\xampp\mysql') -or (Get-Process mysqld,mariadbd -ErrorAction SilentlyContinue) -or $dbData.Count) {
  # config-file facts: datadir / bind / port / socket -- read-only
  foreach($ini in @('C:\xampp\mysql\bin\my.ini','C:\ProgramData\MySQL\MySQL Server*\my.ini','C:\Program Files\MySQL\MySQL Server*\my.ini','C:\ProgramData\MariaDB\*\my.ini')){
    Get-ChildItem $ini -File -Force -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object {
      $facts = Select-String -LiteralPath $_.FullName -Pattern '^(datadir|port|bind-address|socket)\s*=' -ErrorAction SilentlyContinue | ForEach-Object { $_.Line.Trim() }
      if ($facts) { Note "DB config $($_.FullName): $($facts -join ' ; ')" }
    }
  }
  if ($dbData.Count) { Waldo ("Non-stock DB schema dirs (app data on disk): " + (($dbData.Name | Select-Object -Unique) -join ', ')) }
  Add-Lead 84 "Local app DB likely holds crackable creds (READ IT LOCALLY FIRST)" "MySQL/MariaDB present + app source -> a users/creds table usually holds hashes (32-hex = raw MD5, `$2y`$ = bcrypt, `$P`$ = phpass). Remote DB login often fails while the local DB is readable -- so read it ON-BOX (mysql -u root, or read the .MYD/ibdata files) BEFORE remote guessing. Waldo does not connect or test credentials. Manual review." -CanonicalSource 'local-app-db-crackable' -Consumer 'local-database' -Primitive 'credential-store-local-db'
  if ($script:DbListener -match '3306|3307') { Info "  (a local MySQL/MariaDB listener is up -- but if REMOTE login fails/handshake errors, the local on-box read is the higher-signal path.)" }
}

Sub "XAMPP / stock default credential files"
foreach($xf in @('C:\xampp\passwords.txt','C:\xampp\security\webdav.htpasswd','C:\xampp\readme_en.txt')){
  if (Test-Path -LiteralPath $xf) { Waldo "$xf"; Add-Lead 45 "[DEFAULT/BOILERPLATE] XAMPP creds file: $xf" "Stock XAMPP default strings (wampp / ppmax2011 / xampp-dav-unsecure) -- low-value boilerplate; note only, and don't let it outrank app source / DB hashes / LSA. Waldo does not test." -CanonicalSource (Redact-ForId "$xf") -Consumer 'default-boilerplate-xampp-creds-file' -Primitive 'default-boilerplate-xampp-creds-file' }
}

Sub "Sensitive loot staged under a web-served path (OPSEC -- may be downloadable)"
foreach($wr2 in ($webroots | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $wr2)) { continue }
  Get-ChildItem $wr2 -Recurse -Depth 3 -Include '*.save','*.hive','SAM','SYSTEM','SECURITY','NTDS.dit','*.dmp','mimikatz*','*hashes*','waldo*.txt' -File -Force -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object {
    Jackpot "sensitive loot is WEB-SERVED: $($_.FullName)"
    Add-Lead 70 "Sensitive loot under web root: $($_.FullName)" "A hive/dump/output/loot file sits under a served web dir -- likely downloadable by anyone hitting the site. Pull it and REMOVE it after use. Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'sensitive-loot-under-web-root' -Primitive 'sensitive-loot-under-web-root'
  }
}
Sub "Exposed .git in web/app roots (dump history -- removed creds often recoverable)"
# bounded to web/transfer roots (NOT all AppRoots -- avoids recursing huge C:\ProgramData)
$gitRoots = @('C:\inetpub','C:\wwwroot','C:\www','C:\xampp\htdocs','C:\wamp\www','C:\wamp64\www','C:\laragon\www','C:\transfer','C:\Tools','C:\Apps')
foreach($gr in ($gitRoots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)){
  Get-ChildItem $gr -Recurse -Depth 3 -Filter '.git' -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First 6 | ForEach-Object {
    Jackpot ".git repo in web/app root: $($_.FullName)"
    Add-Lead 84 "Exposed .git metadata: $($_.FullName)" "Deployed .git directory -- reconstruct history (git log / checkout old revisions); credentials removed in later commits are often recoverable. Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'exposed-git-metadata' -Primitive 'exposed-git-metadata'
    Add-CredArtifact 'git history (removed creds often recoverable)' $_.FullName
  }
}
Sub "Backup images / archives in web/app/backup roots (staged hives & creds)"
# bounded to backup/web/transfer roots (NOT C:\ProgramData)
$imgRoots = @('C:\Backup','C:\Backups','C:\transfer','C:\inetpub','C:\wwwroot','C:\www','C:\Temp','C:\Tools','C:\Data')
foreach($ir in ($imgRoots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)){
  Get-ChildItem $ir -Recurse -Depth 3 -Include '*.vhd','*.vhdx','*.vmdk','*.ova','*.ovf','*.7z','*.zip','*.bak','*.old','*.tar','*.gz' -File -Force -ErrorAction SilentlyContinue | Select-Object -First 12 | ForEach-Object {
    Jackpot "backup image/archive: $($_.FullName)  ($([math]::Round($_.Length/1MB)) MB)"
    Add-Lead 78 "Backup image/archive: $($_.FullName)" "Backup image/archive may contain staged registry hives, configs, or credential files. Exfil & inspect offline. Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'backup-image-archive' -Primitive 'backup-image-archive'
    Add-CredArtifact 'backup image/archive' $_.FullName
  }
}
Sub "Registry hive backups (readable SAM/SYSTEM/SECURITY = offline hash extraction)"
$hiveDirs = @("$env:WINDIR\System32\config","$env:WINDIR\System32\config\RegBack","$env:WINDIR\Repair",
  'C:\Windows.old\Windows\System32\config','C:\Windows.old\Windows\Repair')
$foundSam=$false; $foundSys=$false
foreach($d in ($hiveDirs | Select-Object -Unique)){
  if (-not (Test-Path -LiteralPath $d)) { continue }
  foreach($n in @('SAM','SYSTEM','SECURITY')){
    $p = Join-Path $d $n
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $readable = $false
    try { $fs = [IO.File]::Open($p,'Open','Read','ReadWrite'); $fs.Close(); $readable = $true } catch {}
    if ($readable) { Jackpot "READABLE hive: $p"; Add-CredArtifact 'registry hive (NTLM -> secretsdump LOCAL)' $p; if($n -eq 'SAM'){$foundSam=$true}; if($n -eq 'SYSTEM'){$foundSys=$true} }
    else { Denied "hive present but locked/denied: $p" }
  }
}
# loose hive copies / .bak in Windows.old and custom roots (extensionless, Scan-Zone misses them)
foreach($hz in @('C:\Windows.old','C:\Temp','C:\Backup','C:\Backups','C:\transfer')){
  if (-not (Test-Path -LiteralPath $hz)) { continue }
  Get-ChildItem $hz -Recurse -Depth 4 -Include 'SAM','SYSTEM','SECURITY','NTDS.dit','SAM.bak','SYSTEM.bak','*.hive','*.hiv','*.save','sam.save','system.save','security.save','*_sam*','*_system*' -File -Force -ErrorAction SilentlyContinue |
    Select-Object -First 12 | ForEach-Object { Jackpot "hive/NTDS copy: $($_.FullName)"; Add-CredArtifact 'registry hive / NTDS copy' $_.FullName; if($_.Name -ieq 'SAM'){$foundSam=$true}; if($_.Name -ieq 'SYSTEM'){$foundSys=$true}; if($_.Name -ieq 'NTDS.dit'){ Add-Lead 92 "NTDS.dit copy readable: $($_.FullName)" "Domain hash database -- extract offline (secretsdump -ntds ... LOCAL) with the SYSTEM hive. Manual review." -CanonicalSource (Redact-ForId "$($_.FullName)") -Consumer 'ntds-dit-copy-readable' -Primitive 'ntds-dit-copy-readable' } }
}
if ($foundSam -and $foundSys) {
  $hb = if ($script:DomainJoined) { 95 } else { 90 }
  $dm = if ($script:DomainJoined) { " This host is DOMAIN-JOINED: old hives / Windows.old often hold admin-named account hashes -- preserve each as an exact pair with origin scope and corroborate scope before crossing to domain/DC. Waldo does not test/reuse." } else { "" }
  Add-Lead $hb "Readable SAM + SYSTEM hive backups" "Backup registry hives are readable -- extract local hashes offline (impacket-secretsdump -sam SAM -system SYSTEM LOCAL) without admin.$dm Manual review." -CanonicalSource 'readable-sam-system-hives' -Consumer 'hive-backup' -Primitive 'offline-hash-dump'
}
elseif ($foundSys)            { Add-Lead 72 "Readable SYSTEM hive backup" "SYSTEM hive readable (boot key / LSA material) -- pair with a SAM or SECURITY copy for offline extraction. Manual review." -CanonicalSource 'readable-system-hive' -Consumer 'hive-backup' -Primitive 'hive-backup' }

Sub "Winlogon autologon (cleartext DefaultPassword)"
try {
  $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
  if ($wl.AutoAdminLogon -eq '1' -or $wl.DefaultPassword) {
    Jackpot "AutoAdminLogon=$($wl.AutoAdminLogon)  user=$($wl.DefaultDomainName)\$($wl.DefaultUserName)"
    if ($wl.DefaultPassword) { Jackpot "  DefaultPassword (CLEARTEXT): $($wl.DefaultPassword)"; Add-Lead 90 "Winlogon autologon cleartext password" "HKLM Winlogon stores a cleartext DefaultPassword for $($wl.DefaultUserName). Preserve the exact user/password pair with origin scope; any use is your manual decision. Waldo does not test/reuse." -CanonicalSource 'winlogon-defaultpassword' -Consumer 'winlogon-autologon' -Primitive 'credential-cleartext'; Add-CredArtifact 'Winlogon DefaultPassword (cleartext)' "$($wl.DefaultUserName)" $($wl.DefaultUserName) $($wl.DefaultPassword) }
    else { Note "AutoAdminLogon set but DefaultPassword not in cleartext (may be LSA secret DefaultPassword -- reg save HKLM\SECURITY when elevated)." }
  } else { Note "no autologon configured." }
} catch { CovError "Winlogon autologon (cleartext DefaultPassword) probe failed: $($_.Exception.Message)" }

# =====================================================================
#  12b. SYSTEM/ELEVATED COLLECTION  --  only runs (or only pays off) when elevated
# =====================================================================
if ($script:Elevated -and (Want 'collection')) {
  Head "SYSTEM collection -- reachable only at this privilege (not privesc; loot)"
  Info "Elevated as $($script:Ctx): the low-priv writable findings are suppressed. Collect instead:"
  Sub "Live registry hives (now reg save-able as SYSTEM)"
  Info "reg save HKLM\SAM sam; reg save HKLM\SYSTEM sys; reg save HKLM\SECURITY sec  ->  secretsdump -sam sam -system sys -security sec LOCAL"
  Info "  ('SECURITY' gives LSA secrets + cached domain creds/DCC2 for offline crack)."
  Info "  In the LSA dump, _SC_<service> secrets = CLEARTEXT service-account passwords (e.g. _SC_cloudbase-init) -- frequently reused across hosts. Manual review."
  # make the SECURITY/LSA path a top-ranked collection lead
  Add-Lead 95 "SYSTEM: dump SECURITY/LSA secrets FIRST (not just SAM)" "reg save HKLM\SECURITY sec (+SAM +SYSTEM) -> secretsdump LOCAL. LSA _SC_<service> secrets are cleartext service-account passwords and are OFTEN DOMAIN creds. Do this before/alongside SAM. Manual review." -CanonicalSource 'lsa-secrets-collection' -Consumer 'elevated-collection' -Primitive 'collection-lsa-secrets'
  Add-CredArtifact 'LSA/SECURITY _SC_ service secrets (often domain creds)' 'reg save HKLM\SECURITY -> secretsdump LOCAL'
  Sub "LSASS (cached logons / plaintext / tickets -- dump then parse offline)"
  try { $ls = Get-Process lsass -ErrorAction SilentlyContinue; if ($ls) { Info "lsass PID $($ls.Id) -- dump: rundll32 comsvcs.dll MiniDump $($ls.Id) C:\Temp\l.dmp full  ->  pypykatz/mimikatz offline." ; Add-CredArtifact 'LSASS dump target (cached creds/tickets)' "PID $($ls.Id)" } } catch { CovError "LSASS dump-target enumeration failed: $($_.Exception.Message)" }
  # who is LOGGED ON? a domain/admin session in LSASS is the pivot
  $daSession = $false
  try {
    $sessions = @(); $sessions += (qwinsta 2>$null); $sessions += (query user 2>$null)
    $sessions | Where-Object { $_ -and $_ -notmatch '(?i)SESSIONNAME|USERNAME|^\s*$' } | Select-Object -Unique | ForEach-Object {
      $s = $_.Trim(); Waldo "session: $s"
      if ($s -match '(?i)(administrator|adm[_-]|\-da\b|domain admin|\bda\b|svc[_-]?adm)') { $daSession = $true }
    }
    (Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | ForEach-Object { $_.Antecedent.Name } | Select-Object -Unique) | Where-Object { $_ -match '(?i)admin' } | ForEach-Object { $daSession = $true; Note "logged-on admin-ish account: $_" }
  } catch { CovError "elevated active-session enumeration (qwinsta/query user/LoggedOnUser) failed -- admin-session lead may be missed: $($_.Exception.Message)" }
  if ($daSession) { Add-Lead 96 "Domain/admin session present -> dump LSASS NOW" "An admin/domain-admin-looking session is logged on -- LSASS likely holds a reusable domain/admin credential. Prioritize the LSASS dump. Manual review." -CanonicalSource 'domain-admin-session-present-dump-lsass-now' -Consumer 'domain-admin-session-present-dump-lsass-now' -Primitive 'domain-admin-session-present-dump-lsass-now' }
  Sub "Machine account (HOSTNAME`$) usefulness"
  Info "If the SYSTEM/SECURITY dump yields a HOSTNAME`$ (machine) NTLM/AES: not interactive, but still auth for LDAP/SMB READ and BloodHound collection as the computer account. Manual review."
  Sub "OTHER USERS' saved sessions (HKCU is SYSTEM's own & empty -- the win is in HKU/NTUSER.DAT)"
  # loaded user hives under HKU
  try {
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-.*\d$' } | ForEach-Object {
      $sid = $_.PSChildName
      foreach($sub in @('Software\SimonTatham\PuTTY\Sessions','Software\Martin Prikryl\WinSCP 2\Sessions')){
        $kp = "Registry::HKEY_USERS\$sid\$sub"
        if (Test-Path $kp) {
          Get-ChildItem $kp -ErrorAction SilentlyContinue | ForEach-Object {
            $sp = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            Jackpot "[$sid] $($sub.Split('\')[1]) session '$($_.PSChildName)': $($sp.HostName) user=$($sp.UserName)"
            Add-CredArtifact 'other-user saved session (HKU)' "$sid $($_.PSChildName) -> $($sp.HostName)"
          }
        }
      }
    }
  } catch { CovError "other-user saved-session (HKU/NTUSER.DAT) enumeration failed: $($_.Exception.Message)" }
  # unloaded profiles -- point at their NTUSER.DAT for offline extraction
  Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $nt = Join-Path $_.FullName 'NTUSER.DAT'
    if (Test-Path -LiteralPath $nt) { Note "NTUSER.DAT ($($_.Name)) -> load offline (reg load) to read their PuTTY/WinSCP/autologon: $nt" }
  }
}

# =====================================================================
#  13. DEEP EXTRAS
# =====================================================================
if ($script:DeepMode) {
  Head "Deep extras (default; off under -Medium/-Light)"
  Sub "AlwaysInstallElevated (both hives set = possible SYSTEM via .msi)"
  $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
  $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
  if ($hklm) { Jackpot "HKLM AlwaysInstallElevated = $hklm" }
  if ($hkcu) { Jackpot "HKCU AlwaysInstallElevated = $hkcu" }
  # explicit verdict (never leave a bare heading)
  if ($hklm -eq 1 -and $hkcu -eq 1) { Add-Lead 92 "AlwaysInstallElevated enabled (both hives)" "Both hives set -- any .msi installs as SYSTEM. Build an msi payload. Possible privesc condition. Manual review." -CanonicalSource 'alwaysinstallelevated' -Consumer 'msi-policy' -Primitive 'privesc-msi' }
  else { Info ("VERDICT AlwaysInstallElevated: NOT exploitable (HKLM=" + $(if($null -eq $hklm){'missing'}else{$hklm}) + " HKCU=" + $(if($null -eq $hkcu){'missing'}else{$hkcu}) + " -- both must be 1).") }

  Sub "Event Log quick search (proof/flag/creds leaking into logs)"
  $evtHits = 0; $evtDenied = $false
  foreach($ln in @('Application','System','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')){
    try {
      Get-WinEvent -LogName $ln -MaxEvents 400 -ErrorAction Stop |
        Where-Object { $_.Message -match 'proof\.txt|local\.txt|cloudbase|qemu|guest-exec|sshpass|plink|password\s*[:=]' } |
        Select-Object -First 5 | ForEach-Object {
          $m = ($_.Message -replace '\s+',' '); $m = $m.Substring(0,[Math]::Min(160,$m.Length))
          Waldo "evt[$ln]: $m"; Add-CredArtifact 'event-log secret/flag reference' $ln; $evtHits++
        }
    } catch { if ("$_" -match 'access|denied|permission') { $evtDenied = $true } }
  }
  if ($evtHits -eq 0) { Info ("VERDICT Event-log quick search: " + $(if($evtDenied){'access denied to some logs (retry elevated)'}else{'no credential/flag hits'}) + ".") }

  Sub "Installed software (full non-Microsoft list -- with version + path)"
  # for KNOWN server products, turn 'product installed' into concrete local evidence
  # (install path, version, config/service account) rather than just the name.
  $serverProd = '(?i)ManageEngine|AppManager|Jenkins|GitLab|TeamCity|Tomcat|JBoss|WildFly|Jira|Confluence|SolarWinds|Nagios|Zabbix|PRTG|Splunk|Elasticsearch|Grafana|Jamf|Zoho|ServiceDesk'
  foreach($uk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')){
    Get-ItemProperty $uk -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.Publisher -notmatch 'Microsoft' } | Sort-Object DisplayName -Unique | ForEach-Object {
      $p = $_
      Note ("$($p.DisplayName)$(if($p.DisplayVersion){" v$($p.DisplayVersion)"})$(if($p.InstallLocation){"  @ $($p.InstallLocation)"})")
      if ($p.DisplayName -match $serverProd) {
        Waldo "server product: $($p.DisplayName)$(if($p.DisplayVersion){" v$($p.DisplayVersion)"})"
        $il = $p.InstallLocation
        $cfgHits = @()
        if ($il -and (Test-Path -LiteralPath $il)) {
          $cfgHits = Get-ChildItem $il -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue -Include '*.conf','*.xml','*.properties','*.ini','*.yml','*.yaml','web.config','wrapper.conf','*.cfg' | Select-Object -First 12 | ForEach-Object { $_.FullName }
        }
        # service run-as for this product
        $svcAcct = try { (Get-Cim Win32_Service | Where-Object { $_.PathName -and $il -and $_.PathName -match [regex]::Escape($il) } | Select-Object -First 1).StartName } catch { $null }
        Add-Lead 62 "Server product installed: $($p.DisplayName)" ("Concrete local surface -- version $($p.DisplayVersion); path $il$(if($svcAcct){"; runs as $svcAcct"}). Config files to read for creds: " + (($cfgHits | Select-Object -First 6) -join ', ') + ". Rank its CONFIGS/secrets above the product name; check for a known local-config credential before chasing a remote product exploit. Manual review.") -CanonicalSource (Redact-ForId "$($p.DisplayName)") -Consumer 'server-product-installed' -Primitive 'server-product-installed'
        foreach($cf in ($cfgHits | Select-Object -First 6)){ Add-CredArtifact "server-product config ($($p.DisplayName))" $cf }
      }
    }
  }
}

# =====================================================================
#  HIGH-SIGNAL SOFTWARE  --  breadcrumbs even before creds are found (always on)
# =====================================================================
}
if (Want 'creds') {
Head "High-signal software -- saved-session / cred-bearing apps installed"
$rcSoft = 'PuTTY|WinSCP|FileZilla|mRemoteNG|SuperPuTTY|MobaXterm|RealVNC|TightVNC|UltraVNC|VNC|TeamViewer|AnyDesk|Remote Desktop Connection Manager|RDCMan|KeePass|WiFi Mouse|Mouse Server|pgAdmin|HeidiSQL|DBeaver|OpenVPN'
$rcFound = $false
foreach($uk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')){
  Get-ItemProperty $uk -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $rcSoft } | ForEach-Object {
    $rcFound = $true
    Waldo "installed: $($_.DisplayName)"
    Add-AppSignal $_.DisplayName 'installed'
    Add-Lead 70 "Saved-session / cred-bearing software: $($_.DisplayName)" "This app commonly stores saved sessions/credentials (host+user+pass) -- hunt its config/registry. A strong breadcrumb even before a cred is found. Manual review." -CanonicalSource (Redact-ForId "$($_.DisplayName)") -Consumer 'saved-session-cred-bearing-software' -Primitive 'saved-session-cred-bearing-software'
    Add-CredArtifact 'saved-session app installed' $_.DisplayName
  }
}
if (-not $rcFound) { Info "None of the usual saved-session/cred apps found in the uninstall registry." }

# =====================================================================
#  v2.16 A5 -- VNC: broad presence/role/format flag (A5a, always-on) + exact decode (A5b, opt-in)
# =====================================================================
Sub "VNC -- presence/role/format (A5a); decode only supported formats with -DecodeLocalSecrets (A5b)"
# A5b DES: fixed key {23,82,107,6,35,78,88,7}, each byte BIT-REVERSED so standard DES matches d3des.
# KAT-validated vs pycryptodome + openssl. ECB/no-pad, C-string (stop at first null).
function Decode-VncDes([byte[]]$Blob){
  if (-not $Blob -or $Blob.Length -lt 8) { return $null }
  try {
    $key = [byte[]](0xE8,0x4A,0xD6,0x60,0xC4,0x72,0x1A,0xE0)
    $des = [System.Security.Cryptography.DES]::Create(); $des.Mode='ECB'; $des.Padding='None'; $des.Key=$key
    $out = $des.CreateDecryptor().TransformFinalBlock($Blob,0,8)
    $n = [Array]::IndexOf($out,[byte]0); if($n -lt 0){$n=8}
    return [System.Text.Encoding]::ASCII.GetString($out,0,$n)
  } catch { return $null }
}
# UltraVNC ini value = 18-hex profile-struct record (8 data + 1 checksum); GetPrivateProfileStruct VALIDATES the checksum.
try { Add-Type -Namespace Waldo -Name Ini -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Ansi, SetLastError=true)]
public static extern bool GetPrivateProfileStructA(string section, string key, byte[] buf, uint size, string file);
'@ -ErrorAction SilentlyContinue } catch {}
function Read-UvncIni([string]$File,[string]$Key){
  try { $buf = New-Object byte[] 8; if ([Waldo.Ini]::GetPrivateProfileStructA('ultravnc',$Key,$buf,8,$File)) { return ,([byte[]]$buf) } } catch {}
  return $null
}
function Emit-VncDecode($origin,$scope,$blob){
  if (-not $blob) { return }
  $pt = Decode-VncDes ([byte[]]$blob)
  if ($pt) {
    Jackpot "  VNC decode ($scope): $(if($NoContent){'[--NoContent]'}else{$pt})"
    Add-Lead 84 "[!!] VNC secret decoded ($scope)" "origin=$origin scope=$scope transformation=fixed-key-local-decode UNTESTED -- reversible local secret decoded offline. Waldo does NOT connect or reuse it; validate manually. Value: $(if($NoContent){'[hidden -NoContent]'}else{$pt})" -CanonicalSource (Redact-ForId $origin) -Consumer "vnc:$scope" -Primitive 'vnc-secret-decoded'
    Add-CredArtifact "VNC $scope (untested)" $origin
  }
}
# v0.15 A5a: independent state model (role/activity/auth_mode/artifact_state/format/decode_state). Fact from active svc/proc.
# v0.34 A5: full role model -- server / viewer / installed_only / unknown, with local process/service attribution for a
#           listener and hypothesis-only handling for an unattributed port. All read-only; Waldo never connects.
$vncServerProc = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^(winvnc|uvnc_service|tvnserver|vncserver|x11vnc)' })
$vncServerSvc  = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)vnc' -and $_.Status -eq 'Running' })
$vncViewerProc = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^(vncviewer|tvnviewer|uvnc_.*viewer|ssvncviewer)' })
# Listener attribution: any local LISTEN on the VNC port range, mapped to its owning process (read-only).
$vncListeners = @()
try {
  foreach($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -ge 5900 -and $_.LocalPort -le 5906 })){
    $op = $null; try { $op = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue } catch {}
    $vncListeners += [pscustomobject]@{ Port=$c.LocalPort; Addr=$c.LocalAddress; Pid=$c.OwningProcess; Proc=($op.ProcessName); Attributed=[bool]$op }
  }
} catch { CovError "VNC listener attribution (Get-NetTCPConnection) failed -- role/activity may be understated: $($_.Exception.Message)" }
# Installed-but-passive: a VNC uninstall entry with no running server/viewer/listener.
$vncInstalled = $false
try { foreach($uk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')){ if (Get-ItemProperty $uk -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '(?i)vnc' }) { $vncInstalled = $true } } } catch { CovError "VNC installed-product enumeration failed: $($_.Exception.Message)" }
$vncActive = ($vncServerProc.Count -gt 0) -or ($vncServerSvc.Count -gt 0) -or (@($vncListeners | Where-Object { $_.Attributed }).Count -gt 0)
# A5 declared enums (fact vs hypothesis kept SEPARATE -- never a '/'-joined role): role in {server, client, unknown};
# activity in {active, installed_only, unknown}. An unattributed listener does NOT set role/activity to a server claim
# -- it is emitted as a hypothesis-only lead below (role stays unknown here).
$vncRole = if ($vncActive) { 'server' }
           elseif ($vncViewerProc.Count -gt 0) { 'client' }
           else { 'unknown' }
$vncActivity = if ($vncActive) { 'active' }
               elseif ($vncViewerProc.Count -gt 0) { 'unknown' }   # a running viewer is a client; no server-activity claim
               elseif ($vncInstalled) { 'installed_only' }
               else { 'unknown' }
$dstate = if ($DecodeLocalSecrets) { 'requested' } else { 'not_requested' }
# Emit the attribution facts (each listener; hypothesis-only wording when unattributed). Read-only, no probing.
foreach($l in $vncListeners){
  if ($l.Attributed) { Info "VNC listener $($l.Addr):$($l.Port) -> $($l.Proc) (pid $($l.Pid))" }
  else { Add-Lead 58 "VNC listener not attributed to a local process: $($l.Addr):$($l.Port)" "A VNC-range listener is open but Waldo could not tie it to an owning local process (insufficient rights or a namespaced/forwarded listener). HYPOTHESIS ONLY -- treat as a possible server pending manual attribution; Waldo does not connect. Manual review." -CanonicalSource (Redact-ForId "$($l.Addr)") -Consumer 'vnc-listener-not-attributed-to-a-local-process' -Primitive 'vnc-listener-not-attributed-to-a-local-process' }
}
function Add-VncLead($score,$title,$origin,$role,$activity,$auth,$astate,$format,$decode,$note){
  $stale = if ($activity -eq 'active') { 'false' } else { 'true' }
  $staleNote = if ($stale -eq 'true') { ' No running VNC server observed -- this secret may be stale (verify it maps to a live service before relying on it).' } else { '' }
  # v0.42 A5: record the state as INDEPENDENT TYPED FIELDS (also emitted to JSON), in addition to the human prose.
  [void]$script:VncFindings.Add([pscustomobject]@{ origin=$origin; role=$role; activity=$activity; stale_possible=[bool]($stale -eq 'true'); auth_mode=$auth; artifact_state=$astate; format=$format; decode_state=$decode })
  Add-Lead $score $title ("role=$role activity=$activity stale_possible=$stale auth_mode=$auth artifact_state=$astate format=$format decode_state=$decode. $note$staleNote Waldo does not test/reuse.") "VNC artifact at $origin" "confirm the record/format; decode only supported reversible records with -DecodeLocalSecrets" "credential-material" -CanonicalSource (Redact-ForId $origin) -Consumer "vnc:$role" -Primitive "vnc-secret-$format"
}
Info "VNC role=$vncRole activity=$vncActivity  decode=$([bool]$DecodeLocalSecrets)  (A5a classifies; A5b decodes only validated reversible records)"
# v0.34 A5: signature coverage -- checked / present / not_found / denied, so an empty result is an ASSERTED absence, not a gap.
$vncSig = @{ checked=0; present=0; not_found=0; denied=0 }
# 1) UltraVNC ini -- VALIDATE the 18-hex profile-struct record BEFORE labeling reversible
foreach($ini in @("$env:ProgramFiles\uvnc bvba\UltraVNC\ultravnc.ini","${env:ProgramFiles(x86)}\uvnc bvba\UltraVNC\ultravnc.ini","$env:ProgramFiles\UltraVNC\ultravnc.ini")){
  $vncSig.checked++
  if (-not (Test-Path -LiteralPath $ini)) { $vncSig.not_found++; continue }
  foreach($vk in @(@{k='passwd';scope='UltraVNC-incoming (passwd)'}, @{k='passwd2';scope='UltraVNC-viewonly (passwd2)'})){
    $present = [bool]((Get-Content -LiteralPath $ini -ErrorAction SilentlyContinue) | Select-String -Pattern "^$($vk.k)=" -Quiet)
    if (-not $present) { continue }
    $vncSig.present++
    $blk = Read-UvncIni $ini $vk.k                    # validated 8-byte block (checksum OK) or $null
    if ($null -eq $blk) {
      Add-VncLead 55 "VNC INI value malformed: $ini [$($vk.k)]" $ini $vncRole $vncActivity 'vnc_password' 'present' 'unknown_format' 'malformed' "The $($vk.k) value did not validate as an 18-hex profile-struct record -- informational only, NOT decoded."
      continue
    }
    Jackpot "UltraVNC config: $ini [$($vk.k)] (valid 18-hex record)"
    Add-VncLead 78 "VNC secret present ($($vk.scope)): $ini" $ini $vncRole $vncActivity 'vnc_password' 'present' 'reversible_supported' $dstate "Valid fixed-key record."
    if ($DecodeLocalSecrets) { Emit-VncDecode $ini $vk.scope $blk }
  }
}
# 2) registry stores -- REG_BINARY 8-byte raw, fixed-key (WinVNC3/ORL incl. \Default, TightVNC, legacy RealVNC)
$vncRegStores = @(
  @{ path='HKLM:\SOFTWARE\ORL\WinVNC3';                     vals=@('Password'); fam='WinVNC3' }
  @{ path='HKLM:\SOFTWARE\ORL\WinVNC3\Default';             vals=@('Password'); fam='WinVNC3' }
  @{ path='HKLM:\SOFTWARE\WOW6432Node\ORL\WinVNC3';         vals=@('Password'); fam='WinVNC3' }
  @{ path='HKLM:\SOFTWARE\WOW6432Node\ORL\WinVNC3\Default'; vals=@('Password'); fam='WinVNC3' }
  @{ path='HKCU:\SOFTWARE\ORL\WinVNC3';                     vals=@('Password'); fam='WinVNC3' }
  @{ path='HKCU:\SOFTWARE\ORL\WinVNC3\Default';             vals=@('Password'); fam='WinVNC3' }
  @{ path='HKLM:\SOFTWARE\TightVNC\Server';                 vals=@('Password','ControlPassword'); fam='TightVNC' }
  @{ path='HKLM:\SOFTWARE\RealVNC\Default';                 vals=@('Password'); fam='RealVNC-legacy' }
  @{ path='HKCU:\SOFTWARE\RealVNC\Default';                 vals=@('Password'); fam='RealVNC-legacy' }
  # Modern RealVNC (VNC Server 5+/6+/7+) -- the 'vncserver' store; its password is a NON-reversible salted (PBKDF2-family) value.
  @{ path='HKLM:\SOFTWARE\RealVNC\vncserver';               vals=@('Password'); fam='RealVNC-modern' }
  @{ path='HKLM:\SOFTWARE\WOW6432Node\RealVNC\vncserver';   vals=@('Password'); fam='RealVNC-modern' }
  @{ path='HKCU:\SOFTWARE\RealVNC\vncserver';               vals=@('Password'); fam='RealVNC-modern' }
)
foreach($rs in $vncRegStores){
  foreach($vn in $rs.vals){ $vncSig.checked++ }
  if (-not (Test-Path -LiteralPath $rs.path)) { $vncSig.not_found += $rs.vals.Count; continue }
  $rerr = $null
  $rp = Get-ItemProperty -LiteralPath $rs.path -ErrorAction SilentlyContinue -ErrorVariable rerr
  if (($null -eq $rp) -and $rerr -and ("$($rerr[0].Exception.Message)" -match '(?i)denied')) { $vncSig.denied += $rs.vals.Count; continue }
  foreach($vn in $rs.vals){
    $raw = $rp.$vn; if (-not $raw) { $vncSig.not_found++; continue }
    $vncSig.present++
    $bytes = [byte[]]$raw
    $vscope = if ($vn -eq 'ControlPassword') { 'TightVNC-control-interface (server_control)' } elseif ($rs.fam -eq 'TightVNC') { 'TightVNC-incoming-session (remote_session)' } else { "$($rs.fam)-incoming" }
    if ($rs.fam -eq 'RealVNC-modern') {
      # Positive recognition by STORE (the 'vncserver' product key). The value is NON-reversible (salted, PBKDF2-family) --
      # decode is not_applicable regardless of length. We do NOT length-guess and we do NOT attempt to crack it.
      Add-VncLead 60 "VNC secret present (RealVNC modern, non-reversible): $($rs.path)\$vn" "$($rs.path)\$vn" $vncRole $vncActivity 'vnc_password' 'present' 'salted_hash' 'not_applicable' "Modern-RealVNC 'vncserver' store: a salted hash (PBKDF2-family), recognized by STORE not length -- structurally NOT the fixed-key format, not decoded."
    } elseif ($bytes.Length -eq 8) {
      Jackpot "VNC secret present: $($rs.path)\$vn (8-byte REG_BINARY)"
      Add-VncLead 78 "VNC secret present ($vscope): $($rs.path)\$vn" "$($rs.path)\$vn" $vncRole $vncActivity 'vnc_password' 'present' 'reversible_supported' $dstate "8-byte fixed-key block (validated by length)."
      if ($DecodeLocalSecrets) { Emit-VncDecode "$($rs.path)\$vn" $vscope $bytes }
    } else {
      # Any other RealVNC-legacy / unrecognized value stays unknown_format -- we never infer 'salted_hash' from length alone.
      Add-VncLead 55 "VNC secret unrecognized ($($bytes.Length) bytes): $($rs.path)\$vn" "$($rs.path)\$vn" $vncRole $vncActivity 'vnc_password' 'present' 'unknown_format' 'unsupported' "Not a supported 8-byte fixed-key blob and not a recognized modern-RealVNC store -- format unknown, informational only, NOT decoded."
    }
  }
}
Info "VNC signature coverage: checked=$($vncSig.checked) present=$($vncSig.present) not_found=$($vncSig.not_found) denied=$($vncSig.denied)  (empty result = asserted absence across the checked stores, not an unrun probe)"
# v0.42 A5: publish the observed role/activity and the structured signature coverage for the JSON manifest.
$script:VncRole = $vncRole; $script:VncActivity = $vncActivity
$script:VncSignature = [ordered]@{ checked=[int]$vncSig.checked; present=[int]$vncSig.present; not_found=[int]$vncSig.not_found; denied=[int]$vncSig.denied }

# =====================================================================
#  CORRELATED APP SIGNALS  --  one target across many classes (Mouse Server model)
# =====================================================================
}
Head "Correlated app signals -- one target across multiple classes (investigate together)"
$corr = @($script:AppSignals.GetEnumerator() | Where-Object {
  $_.Value.Keys.Count -ge 3 -or ($_.Value.ContainsKey('writable') -and ($_.Value.ContainsKey('autorun') -or $_.Value.ContainsKey('service')))
} | Sort-Object { $_.Value.Keys.Count } -Descending)
if ($corr.Count -eq 0) { Info "No single app spanned 3+ signal classes (or writable + autorun/service)." }
else {
  foreach($c in $corr){
    $tags = (($c.Value.Keys) | Sort-Object) -join ', '
    $strong = $c.Value.ContainsKey('writable') -and ($c.Value.ContainsKey('autorun') -or $c.Value.ContainsKey('service'))
    if ($strong) { Jackpot "$($c.Key): $tags" } else { Waldo "$($c.Key): $tags" }
    Add-Lead ($(if($strong){92}else{76})) "Correlated target '$($c.Key)' spans: $tags" "One app/vendor appears across multiple signal classes ($tags) -- the Mouse Server pattern. Highest-confidence local target: investigate these facts as ONE finding. Manual review." -CanonicalSource (Redact-ForId "$($c.Key)") -Consumer 'correlated-target-spans' -Primitive 'correlated-target-spans'
  }
}

# =====================================================================
#  FLAG HUNT  --  local.txt / proof.txt (the objective)
# =====================================================================
if (Want 'flags') {
Head "Flag hunt -- local.txt / proof.txt"
try {
  $flagRoots = @('C:\Users') + ($AppRoots | Where-Object { $_ -notmatch 'ProgramData' -and (Test-Path -LiteralPath $_) })
  $flagNames = @('local.txt','proof.txt','flag.txt','root.txt','user.txt')
  # v0.32 B5: per-root search with FULL bounds accounting -- depth, cap, cap-hit (TRUNCATED), recursive access-denials
  # (captured via -ErrorVariable, not just root readability), and status. A root is 'complete' only if it hit no
  # recursive denial and was not truncated. absence != asserted absence.
  $script:FlagSearchEvidence = @()
  $flagPartial = $false; $flagDepth = 4; $flagCap = 200
  $bootTime = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime } catch { $null }
  $flags = @()
  # top-level of every fixed drive root (C:\, D:\, ...) -- a flag dropped at the drive root
  foreach($drv in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Root -match '^[A-Za-z]:\\$' })){
    $flags += Get-ChildItem $drv.Root -File -Force -ErrorAction SilentlyContinue | Where-Object { $flagNames -contains $_.Name }
  }
  foreach($r in ($flagRoots | Select-Object -Unique)){
    if (-not (Test-Path -LiteralPath $r)) { $script:FlagSearchEvidence += [pscustomobject]@{ root=$r; status='absent' }; continue }
    # v0.41 COV: the recursive per-root search runs under a per-collector DEADLINE. On timeout the root is honestly
    # recorded searched(...,TIMED_OUT) and the class goes PARTIAL rather than asserting a false not-found.
    $out = Invoke-Bounded -What "flag search $r" -ArgumentList @($r,$flagDepth,$flagNames,[bool]$script:HasDepth) -Work {
      param($root,$depth,$names,$hasDepth)
      $err = @()
      $res = if ($hasDepth) { @(Get-ChildItem $root -Recurse -Depth $depth -Include $names -File -Force -ErrorAction SilentlyContinue -ErrorVariable +err) }
             else { @(Get-ChildItem $root -Recurse -Include $names -File -Force -ErrorAction SilentlyContinue -ErrorVariable +err) }
      $deniedN = @($err | Where-Object { ($_.Exception -is [System.UnauthorizedAccessException]) -or ("$($_.Exception.Message)" -match '(?i)denied|is denied|access to the path') }).Count
      [pscustomobject]@{ files=$res; denied=$deniedN }
    }
    if ($null -eq $out) { $script:FlagSearchEvidence += [pscustomobject]@{ root=$r; status="searched(d$flagDepth,TIMED_OUT)" }; $flagPartial = $true; continue }
    $rec = @($out) | Select-Object -Last 1
    $res = @($rec.files); $deniedN = [int]$rec.denied
    $capHit = $false; if ($res.Count -gt $flagCap) { $capHit = $true; $res = @($res | Select-Object -First $flagCap) }
    $st = "searched(d$flagDepth,cap$flagCap"
    if ($deniedN -gt 0) { $st += ",recursive-denied:$deniedN"; $flagPartial = $true }
    if ($capHit) { $st += ",TRUNCATED"; $flagPartial = $true }
    $st += ")"
    $script:FlagSearchEvidence += [pscustomobject]@{ root=$r; status=$st }
    $flags += $res
  }
  $flags = $flags | Sort-Object FullName -Unique | Select-Object -First 20
  if ($flags) {
    foreach($f in $flags){
      # machine-suffixed admin profile (Administrator.<HOST>)
      $suffixed = $f.FullName -match '(?i)\\Users\\(Administrator|Admin)\.[^\\]+\\'
      $owner = try { (Get-Acl -LiteralPath $f.FullName -ErrorAction Stop).Owner } catch { '?' }
      Jackpot "FLAG: $($f.FullName)   (size $($f.Length); owner $owner; modified $($f.LastWriteTime))$(if($suffixed){'   [MACHINE-SUFFIXED ADMIN PROFILE]'})"
      Add-Lead 99 "Flag file: $($f.FullName)" "The objective$(if($suffixed){' -- under a machine-suffixed admin profile (Administrator.<HOST>)'}). Waldo shows the value below, but capture the submission proof yourself: type it in an interactive shell and screenshot with 'whoami' + 'ipconfig' in the same frame." -CanonicalSource (Redact-ForId "$($f.FullName)") -Consumer 'flag-file' -Primitive 'flag-file'
      if ($script:FlagState -ne 'FOUND_READABLE') { $script:FlagState = 'FOUND_DENIED' }
      try {
        $c = Get-Content -LiteralPath $f.FullName -TotalCount 1 -ErrorAction Stop; $script:FlagState = 'FOUND_READABLE'; if (-not $NoContent) { Note "   -> $c" }
        # B5 SUPERSEDED_AFTER_RESET reasoning: mtime vs boot -- a value noted before this file was (re)written is known-stale
        if ($bootTime -and $f.LastWriteTime -ge $bootTime) { $script:FlagSuperseded = $true; Note "   modified $($f.LastWriteTime) (THIS boot, after $bootTime) -- any value you recorded before this is SUPERSEDED_AFTER_RESET (re-read). [structured: flag_superseded_after_reset=true]" }
        elseif ($bootTime) { Note "   modified $($f.LastWriteTime) (predates boot $bootTime -- baked into the image, stable this boot)." }
      } catch { Denied "   (present but not readable -- elevate or get a cred)"; if (-not $script:DeniedFlagPath) { $script:DeniedFlagPath = $f.FullName } }   # A4: retain the exact denied-objective path to cite in the C5 relationship
    }
    # objective-aware nudge -- local.txt present but proof.txt NOT -> the next win is LOCAL elevation here
    $haveLocal = [bool]($flags | Where-Object { $_.Name -ieq 'local.txt' })
    $haveProof = [bool]($flags | Where-Object { $_.Name -ieq 'proof.txt' })
    if ($haveLocal -and -not $haveProof -and -not $script:Elevated) {
      Jackpot "OBJECTIVE: local.txt found, proof.txt NOT -- you need LOCAL privesc on THIS host (not lateral/AD)."
      Add-Lead 93 "Next objective = local privesc on this host" "local.txt is readable but proof.txt is not -- the remaining win is SYSTEM/admin HERE. Prioritize this host's privesc leads (SeImpersonate/service/autostart/hive) over remote/AD/GPO paths. Manual review." -CanonicalSource 'objective-local-privesc' -Consumer 'methodology' -Primitive 'objective-guidance'
    }
    # duplicate / case-variant grouping (e.g. ...\jack\ vs ...\Jack\) -- treat as one objective
    $flags | Group-Object { $_.FullName.ToLower() } | Where-Object { $_.Count -gt 1 } | ForEach-Object {
      $g = ($_.Group.FullName -join '  ')
      Waldo "duplicate/case-variant flag paths: $g"; Add-Lead 55 "Duplicate/case-variant flag paths" "$g -- likely one objective under case-variant/duplicate paths; treat as a single flag (compare size/hash if readable)." -CanonicalSource 'duplicate-case-variant-flag-paths' -Consumer 'duplicate-case-variant-flag-paths' -Primitive 'duplicate-case-variant-flag-paths'
    }
  } else {
    if ($flagPartial) { $script:FlagState = 'SEARCH_PARTIAL'; Info "Flag state: SEARCH_PARTIAL -- at least one root hit a recursive access-denial or was TRUNCATED at the cap (see per-root evidence); absence CANNOT be asserted. Revisit after elevation or widen scope." }
    else { $script:FlagState = 'NOT_FOUND_IN_DECLARED_SEARCH_SCOPE'; Info "Flag state: NOT_FOUND_IN_DECLARED_SEARCH_SCOPE -- EVERY declared root completed within recorded bounds (depth $flagDepth, cap $flagCap, no recursive denials, not truncated), no hit. denied != absent; revisit after elevation or widen scope." }
  }
  Info ("Flag search evidence: " + (($script:FlagSearchEvidence | ForEach-Object { "$($_.root)=$($_.status)" }) -join '  '))
  # denied accounting -- a flag may exist where we can't currently read
  $owed = @()
  Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { -not (Is-Standard $_.Name $Std_CUsers) -or $_.Name -ieq 'Administrator' } | ForEach-Object {
      $un = $_.Name
      foreach($sub in @('Desktop','Documents')){
        $p = Join-Path $_.FullName $sub
        if (Test-Path -LiteralPath $p) { try { [void](Get-ChildItem $p -Force -ErrorAction Stop) } catch { $owed += "$un\$sub" } }
      }
    }
  if ($owed.Count) {
    Denied ("PENDING (denied -- flag may be owed): " + (($owed | Select-Object -Unique) -join ', '))
    Add-Lead 50 "Flags PENDING in denied areas" ("Cannot read: " + (($owed | Select-Object -Unique) -join ', ') + " -- denied != cleared. Revisit after elevation or with a cred.") -CanonicalSource 'flags-pending-denied' -Consumer 'flag-hunt' -Primitive 'flag-denied'
  }
} catch { CovError "flag-hunt collector failed -- flag-state completion may be bypassed: $($_.Exception.Message)" }

# =====================================================================
}
#  RECONCILIATION -- re-check buffered history lines vs the FINAL flagged-binary set
#  (catches a binary flagged AFTER its usage line was already read)
# =====================================================================
if ($script:HistBuf.Count -gt 0 -and $script:FlaggedBins.Count -gt 0) {
  Head "Late correlation -- flagged tools used in earlier history"
  $recN = 0
  foreach($e in $script:HistBuf){
    $ln = [string]$e.Line
    foreach($tok in ($ln -split '\s+')){
      $tb = try { [IO.Path]::GetFileName($tok.Trim('"')) } catch { $tok }
      if (Test-FlaggedBin $tb) { $recN++; Jackpot ("[$($e.Src)] runs flagged '$tb': " + $ln.Substring(0,[Math]::Min(180,$ln.Length))); Add-Lead 88 "Flagged tool '$tb' used (reconciled)" "$ln (from $($e.Src)) -- a binary flagged elsewhere this run is invoked here; any argument (positional password) is high-signal. Manual review." -CanonicalSource (Redact-ForId "$tb") -Consumer 'flagged-tool-used-reconciled' -Primitive 'flagged-tool-used-reconciled'; break }
    }
  }
  if ($recN -eq 0) { Info "No buffered history line referenced a flagged binary." }
}

# DB credential + local DB listener correlation (observation + advice only -- Waldo never connects/dumps)
if ($script:DbCredHint.Count -gt 0 -and $script:DbListener.Count -gt 0) {
  Head "DB access correlation -- creds + a local database"
  Jackpot "DB credential(s) in config + local DB listener present"
  Add-Lead 86 "DB creds + local DB listener -> mine the DB manually" ("Config(s) with DB creds: " + (($script:DbCredHint | Select-Object -Unique) -join ', ') + " ; local DB listener(s): " + (($script:DbListener | Select-Object -Unique) -join ', ') + ". You hold creds AND a reachable local DB -- connect and enumerate it manually (users / password / hash / token columns). If the DB account is a sysadmin/superuser, engine features (MSSQL xp_cmdshell, Postgres COPY ... PROGRAM, MySQL UDF) are a documented local path. Manual review -- no exploit run, Waldo does not connect.") -CanonicalSource 'db-creds-local-listener' -Consumer 'local-database' -Primitive 'credential-store-local-db'
  # v0.15 C1: MSSQL SYSTEM chain requires listener + service identity + LOCAL sa/sysadmin role evidence + local primitive (SeImpersonate)
  if ($script:DbListener -match '1433') {
    $svcId = try { (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^MSSQL' } | Select-Object -First 1).StartName } catch { $null }
    $hasSeImp = try { [bool]((& "$env:WINDIR\System32\whoami.exe" /priv 2>$null) | Select-String -Pattern 'SeImpersonatePrivilege') } catch { $false }
    $roleEv = $false
    foreach($cf in ($script:DbCredHint | Select-Object -Unique)){
      # skip comment lines; require the role as a bounded VALUE, and superuser/sysadmin only when positively enabled (=true) -- 'superuser=false'/comments do not count.
      $roleLines = @(Get-Content -LiteralPath $cf -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*(#|;|--)' })
      if (($roleLines -join "`n") -match "(?i)(user(\s*id)?|uid|username|role)\s*[=:]\s*'?(sa|root|superuser|sysadmin)'?(\W|$)|(is[_ ]?)?(superuser|sysadmin)\s*[=:]\s*(true|yes|on|1)(\W|$)"){ $roleEv=$true; break }
    }
    # v0.34 C1: the strong chain REQUIRES the matching MSSQL SERVICE IDENTITY too (a live local MSSQL service), not just listener+role+primitive.
    if ($hasSeImp -and $roleEv -and $svcId) {
      Add-Lead 88 "MSSQL -> SYSTEM chain (listener + service identity + sa-role config + SeImpersonate)" ("Local MSSQL listener (1433) + a LIVE MSSQL service running as $svcId + a config credential evidencing an sa/sysadmin login + SeImpersonatePrivilege. Documented chain: sysadmin -> xp_cmdshell as $svcId -> SeImpersonate -> Potato (JuicyPotatoNG/PrintSpoofer/GodPotato) -> SYSTEM. Manual review -- Waldo does not connect.") -CanonicalSource 'mssql-system-chain' -Consumer 'mssql-service' -Primitive 'privesc-db-chain'
    } else {
      $missing = @(); if(-not $svcId){$missing += 'no matching MSSQL service identity (live service not found)'}; if(-not $roleEv){$missing += 'no local sa/sysadmin role evidence'}; if(-not $hasSeImp){$missing += 'SeImpersonate not held'}
      Add-Lead 70 "MSSQL present + config credential (chain requires: $($missing -join '; '))" ("Local MSSQL listener (1433) + a config credential" + $(if($svcId){" ; service identity = $svcId"}) + ". A SYSTEM chain REQUIRES a matching live MSSQL service identity AND a locally-evidenced sysadmin/sa login AND SeImpersonate. Missing: $($missing -join '; '). Establish those locally first. Manual review -- Waldo does not connect.") -CanonicalSource (Redact-ForId "$($missing -join '; ')") -Consumer 'mssql-present-config-credential-chain-requires' -Primitive 'mssql-present-config-credential-chain-requires'
    }
  }
}

# v0.15 C5: data-driven relationship vocabulary -- one next-step card per relationship whose facts are BOTH present.
try {
  # C5: distinct segments by REAL network (ip masked by its subnet mask), not a three-octet /24 assumption.
  $segs = @()
  foreach($a in (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue)){
    $ml=@($a.IPSubnet); $j=0
    foreach($ip in @($a.IPAddress)){
      if($ip -match '^\d+\.\d+\.\d+\.\d+$' -and $ip -notmatch '^(127\.|169\.254)'){
        $m = if($j -lt $ml.Count){$ml[$j]}else{'255.255.255.0'}
        try { $ib=[Net.IPAddress]::Parse($ip).GetAddressBytes(); $mb=[Net.IPAddress]::Parse($m).GetAddressBytes(); $nbb=for($k=0;$k -lt 4;$k++){$ib[$k]-band $mb[$k]}; $pfx=(($mb|ForEach-Object{[Convert]::ToString($_,2)}) -join '').Replace('0','').Length; $segs += "$($nbb -join '.')/$pfx" } catch {}
      }
      $j++
    }
  }
  $segs = @($segs | Sort-Object -Unique)
  $ncred = @($script:CredArtifacts | Where-Object { $_ }).Count
  # A4: draw the privilege primitive from ALL registered sources (token privs + writable service/binary/dir), not just whoami /priv
  $primList = @($script:PrivPrimitives | ForEach-Object { $_.Label })
  if (-not $primList.Count) { $primList = @(((& "$env:WINDIR\System32\whoami.exe" /priv 2>$null) | Select-String -Pattern 'Se(Impersonate|AssignPrimaryToken|Backup|Restore|TakeOwnership|Debug|LoadDriver)Privilege' | ForEach-Object { ($_.ToString().Trim() -split '\s+')[0] } | Select-Object -Unique)) }
  $prim = ($primList | Select-Object -First 3) -join '; '
  # v0.34 C5: typed facts. SAVED-ENDPOINT fact = a saved session / client config referencing a REMOTE host (NOT any credential).
  $savedEndpoints = @($script:CredArtifacts | Where-Object { $_.Type -match '(?i)saved.?session|\.rdp|RDP|WinSCP|PuTTY|FileZilla|sitemanager|recentservers|Credential Manager|known.?hosts' }).Count
  $wprim = @($script:PrivPrimitives | Where-Object { $_.Class -eq 'write' } | ForEach-Object { $_.Label } | Select-Object -First 1)
  $c5 = { param($a,$b,$score,$title,$why) if ($a -and $b) { Add-Lead $score $title $why -CanonicalSource ($title -replace '^relationship:\s*','') -Consumer 'c5-relationship-engine' -Primitive 'typed-relationship' } }
  # vocabulary row: SAVED ENDPOINT -> newly reachable segment (narrowed from any-credential+any-segment)
  & $c5 ($savedEndpoints -gt 0) ($segs.Count -ge 2) 64 "relationship: saved endpoint -> newly reachable segment" ("You hold $savedEndpoints SAVED-ENDPOINT artifact(s) (saved session / client config referencing a REMOTE host) AND this box spans segments ($($segs -join ', ')) -- those endpoints likely live on the adjacent segment. Preserve each exact principal/secret pair with its origin scope, tunnel from a foothold on the other segment, and re-run Waldo. Waldo tests nothing.")
  # vocabulary row: EXECUTION SETTING -> writable path -> effective ACL (a write primitive on a SYSTEM-run target)
  & $c5 ([bool]$wprim) $true 63 "relationship: execution setting -> writable path -> SYSTEM exec" ("A SYSTEM-run execution setting references a path you can WRITE ($wprim) -- the effective ACL grants you write, so replacing that path runs as SYSTEM at its next trigger. Confirm the trigger; Waldo writes nothing.")
  # C5: type BOTH sides by ENGINE and require a MATCH -- a MySQL cred config must not pair with a PostgreSQL/MSSQL listener.
  $dbcEng = @(); foreach($cf in ($script:DbCredHint | Where-Object { $_ } | Select-Object -Unique)){
    $ct = try { (Get-Content -LiteralPath $cf -Raw -ErrorAction Stop) } catch { '' }
    if ($ct -match '(?i)mysql|mariadb|:3306|jdbc:mysql') { $dbcEng += 'mysql' }
    if ($ct -match '(?i)postgres|pgsql|:5432|jdbc:postgresql') { $dbcEng += 'postgres' }
    if ($ct -match '(?i)mssql|sqlserver|sql server|:1433|data source=') { $dbcEng += 'mssql' }
  }
  $dblEng = @(); if ($script:DbListener -match '3306'){$dblEng+='mysql'}; if ($script:DbListener -match '5432'){$dblEng+='postgres'}; if ($script:DbListener -match '1433'){$dblEng+='mssql'}
  $dbEngMatch = @($dbcEng | Where-Object { $dblEng -contains $_ } | Select-Object -First 1)
  & $c5 ([bool]$dbEngMatch) $true 60 "relationship: $dbEngMatch credential config -> matching local $dbEngMatch listener" ("A config with $dbEngMatch credentials AND a local $dbEngMatch listener (same engine) are BOTH present -- read the DB locally (it often holds crackable creds) before any remote guessing. Waldo does not connect.")
  # A4: cite BOTH exact facts -- the specific denied objective PATH and the specific primitive.
  & $c5 ($script:FlagState -eq 'FOUND_DENIED') ([bool]$prim) 66 "relationship: denied objective -> available privilege primitive" ("The objective $(if($script:DeniedFlagPath){$script:DeniedFlagPath}else{'(present-but-denied flag)'}) is present-but-denied AND you hold a privilege primitive ($prim) -- elevate with it, then read THAT file. Waldo runs nothing.")
} catch { CovError "C5 relationship correlation failed: $($_.Exception.Message)" }

# host-role inference -- name what this box IS (changes which local files matter)
if (-not $Loot) {
  try {
    $roles = @(); $ev = @()
    if (Get-Service W3SVC,WMSVC -ErrorAction SilentlyContinue) { $roles += 'IIS web server'; $ev += 'W3SVC service' }
    elseif (Test-Path 'C:\inetpub\wwwroot') { $roles += 'IIS web server'; $ev += 'C:\inetpub\wwwroot' }
    if ((Test-Path 'C:\xampp') -or (Get-Process httpd,apache -ErrorAction SilentlyContinue)) { $roles += 'Apache/XAMPP web server'; $ev += 'xampp/apache' }
    if ((Get-Service MSSQLSERVER,'MSSQL$*' -ErrorAction SilentlyContinue) -or (Get-Process sqlservr -ErrorAction SilentlyContinue) -or ($script:DbListener -match '1433')) { $roles += 'MSSQL database server'; $ev += 'sqlservr/1433' }
    if ($script:DbListener -match '3306') { $roles += 'MySQL database server'; $ev += '3306' }
    if (Get-Service NTDS -ErrorAction SilentlyContinue) { $roles += 'DOMAIN CONTROLLER'; $ev += 'NTDS service' }
    if (Test-Path 'C:\Program Files\Microsoft\Exchange Server') { $roles += 'Exchange/mail server'; $ev += 'Exchange Server dir' }
    if (Get-Service W3SVC -ErrorAction SilentlyContinue) {}
    $shareCount = @(Get-CimInstance Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$' }).Count
    if ($shareCount -ge 3) { $roles += 'file server'; $ev += "$shareCount non-default shares" }
    if ($roles.Count) {
      Head "Host role inference (what this box is for)"
      Info ("Inferred role(s): " + (($roles | Select-Object -Unique) -join ' + ') + "   [evidence: " + (($ev | Select-Object -Unique) -join ', ') + "]")
      Add-Lead 48 ("Host role: " + (($roles | Select-Object -Unique) -join ' + ')) ("Evidence: " + (($ev | Select-Object -Unique) -join ', ') + ". Role tells you which local files matter most (web configs / DB dumps / NTDS / mail stores). Manual review.") -CanonicalSource 'host-role' -Consumer 'host-role' -Primitive 'host-role'
    }
  } catch { CovError "host-role inference failed: $($_.Exception.Message)" }
  # credential reuse cross-match -- does a discovered secret name a REAL local account or known host?
  try {
    $localUsers = @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.ToLower() } | Where-Object { $_ -notmatch '^(public|default|default user|all users|administrator)$' })
    $knownHosts = @()
    (Get-Content "$env:WINDIR\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue) | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { ($_ -split '\s+') | Where-Object { $_ -match '[A-Za-z]' } | ForEach-Object { $knownHosts += $_.ToLower() } }
    $xm = @()
    foreach($ca in $script:CredArtifacts){
      $blob = ("$($ca.Type) $($ca.Where)").ToLower()
      foreach($u in ($localUsers | Select-Object -Unique)){ if ($u.Length -ge 3 -and $blob -match "\b$([regex]::Escape($u))\b") { $xm += "secret [$($ca.Type)] references LOCAL user '$u'" } }
      foreach($h in ($knownHosts | Select-Object -Unique)){ if ($h.Length -ge 4 -and $blob -match [regex]::Escape($h)) { $xm += "secret [$($ca.Type)] references known host '$h' -> lateral target" } }
    }
    if ($xm.Count) {
      Head "Credential cross-match (discovered secret <-> real account/host)"
      Info "Correlation only -- Waldo tests nothing."
      ($xm | Select-Object -Unique) | ForEach-Object { Jackpot $_ }
      Add-Lead 74 "Credential cross-match ($(@($xm|Select-Object -Unique).Count) -- secret names a real account/host)" (("A discovered secret names a real local account or a known host: " + (($xm | Select-Object -Unique) -join ' | ')) + ". Preserve each as an exact principal/secret pair with its origin scope; corroborate before crossing scope. Waldo tests/reuses nothing.") -CanonicalSource (Redact-ForId (($xm | Select-Object -Unique) -join '|')) -Consumer 'credential-corroboration' -Primitive 'credential-cross-match'
    }
  } catch { CovError "credential cross-match failed: $($_.Exception.Message)" }
}

# =====================================================================
#  OPERATOR ARTIFACTS  --  likely files WE/prior operators dropped (own bucket, not just suppressed)
# =====================================================================
if (-not $Loot -and $script:OperatorArtifacts.Count -gt 0) {
  Head "Operator artifacts -- likely YOUR/prior-operator files (NOT original lab signal)"
  Info "Name/path matches known tooling/output (waldo*, *peas, chisel, mimikatz, proof-redirect, etc). Kept OUT of top leads so they don't read as 'hidden flag' or 'custom tool'. Delete/ignore -- verify before assuming lab-planted."
  $script:OperatorArtifacts.Keys | Sort-Object | Select-Object -First 40 | ForEach-Object { Note "  ~ $_" }
}

# =====================================================================
#  CREDENTIAL ARTIFACTS  --  clean handoff list (NO spraying/testing done)
# =====================================================================
Head "Credential artifacts -- collect + crack offline; each tagged with scope + tested=false (Waldo never sprays/validates)"
if ($script:CredArtifacts.Count -eq 0) {
  Info "None surfaced from here."
} else {
  Info "Handoff by type: NTLM -> pass-the-hash OR crack;  DCC2 / Kerberoast-TGS / AS-REP / bcrypt / unix-crypt -> crack-only;  cleartext -> scope=unknown until corroborated (Waldo does not spray/test)."
  Info "SCOPE reminder: a cred's source hints its blast radius -- don't mix local-only / domain / service / machine accounts. Verify per host; valid != admin."
  # tag each artifact with an inferred source-class scope (facts only -- no testing)
  $script:CredArtifacts | Sort-Object Type,Where -Unique | ForEach-Object {
    $blob = "$($_.Type) $($_.Where)"
    $scope = if ($blob -match '(?i)NTDS|DCSync|domain hash')       { 'domain-scope (all domain accounts)' }
             elseif ($blob -match '(?i)\$$|machine account|HOST\$'){ 'machine account' }
             elseif ($blob -match '(?i)LSA secret|_SC_|service')   { 'service account (often domain)' }
             elseif ($blob -match '(?i)SAM|local account')         { 'LOCAL account (this host only)' }
             elseif ($blob -match '(?i)app DB|MariaDB|MySQL|creds table|web|config|\.php') { 'app/DB (scope=origin service; corroborate before crossing scope)' }
             elseif ($blob -match '(?i)AD outbound|GPP|SYSVOL')     { 'domain object/right' }
             else { 'scope unknown -- classify before reuse' }
    Say ("  * [$($_.Type)]  $($_.Where)") 'Cyan'
    Say ("      scope: $scope") 'DarkGray'
  }
}

  if ($script:OutFile) { $ofsz = try { (Get-Item -LiteralPath $OutFile -ErrorAction Stop).Length } catch { 0 }; Say "Waldo complete (last section: $script:LastSection).  Saved -> $OutFile ($ofsz bytes -- confirm non-zero before you retrieve/move on)" 'Green' }
  $script:ScanCompleted = $true
} catch {
  # Distinguish a real interruption from a terminating error -- the finally still renders the footer + JSON exactly once.
  if ($_.Exception -is [System.Management.Automation.PipelineStoppedException] -or $_.Exception -is [System.OperationCanceledException]) {
    $script:Interrupted = $true; $script:AbortKind = 'interrupt'
  } else {
    $script:AbortKind = 'error'
    $script:AbortError = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
  }
} finally {
  Emit-Footer
}
