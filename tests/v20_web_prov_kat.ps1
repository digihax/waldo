# v2.20 web/provisioning enumeration KAT.
# Fast source/logic checks for the exam-review additions: web-served artifacts, writable served
# subdirectories, provisioning/Cloudbase logs, unattend files, and readable hive backups.
# Run:  pwsh -NoProfile -File waldo/tests/v20_web_prov_kat.ps1     (exit 0 = all PASS)
$ErrorActionPreference = 'Stop'
$ps1 = Join-Path (Split-Path $PSScriptRoot -Parent) 'waldo.ps1'
$src = Get-Content -LiteralPath $ps1 -Raw
$pass=0;$fail=0
function Chk($desc,$got,$want=$true){
  if($got -eq $want){$script:pass++;"PASS  $desc"}
  else{$script:fail++;"FAIL  $desc (got $got want $want)"}
}
function Has($pattern){ [bool]($src -match $pattern) }

# Served-web artifact coverage: the exam miss was a served script/schema/loot file not named like a normal config.
Chk 'served artifact sweep includes PowerShell scripts' (Has "'\*\.ps1'")
Chk 'served artifact sweep includes SQL/schema files' (Has "'\*\.sql'")
Chk 'served artifact sweep includes registry hive loot extensions' (Has "'\*\.hiv'[^`n]*'\*\.hive'")
Chk 'served high-signal classifier includes simulate/schema/hive/objective terms' (Has '\$hot\s*=.*simulate.*schema.*hive.*local.*proof')
Chk 'custom webroot discovery includes cmsdocs/uploads/images/static' (Has 'cmsdocs\|uploads\?\|files\|images\|static')
Chk 'web-served finding has explicit stable lead identity' (Has "Web-served high-signal file:.*-Consumer 'web-served-high-signal-file'.*-Primitive 'web-served-artifact'")
Chk 'writable served subdirectory is scored separately' (Has "Writable served subdirectory:.*-Consumer 'writable-served-subdirectory'.*-Primitive 'writable-served-subdirectory'")

# Provisioning/answer-file coverage: actual values rank high; boolean injection flags are context only.
Chk 'Cloudbase log/config paths are enumerated' (Has 'Cloudbase Solutions\\Cloudbase-Init\\log\\cloudbase-init\.log')
Chk 'Cloudbase conf and LocalScripts are included' (Has "Cloudbase Solutions\\Cloudbase-Init\\conf','C:\\Program Files\\Cloudbase Solutions\\Cloudbase-Init\\LocalScripts")
Chk 'guest/qemu/cloudbase temp logs are included' (Has "\*qemu\*\.log'.*'\*guest\*\.log")
Chk 'real provisioning values exclude boolean inject_user_password flags' (Has 'inject_user_password\|inject_metadata_password.*true\|false\|yes\|no\|0\|1')
Chk 'Cloudbase injection enabled is context, not captured credential' (Has "Cloudbase password injection enabled:.*-Consumer 'cloudbase-password-injection-enabled'.*-Primitive 'cloudbase-password-injection-enabled'")
Chk 'unattend paths include Panther and Sysprep locations' (Has 'Panther\\Unattend\.xml.*System32\\Sysprep\\unattend\.xml')
Chk 'unattend password lead has explicit identity' (Has "Answer file may hold a password:.*-Consumer 'answer-file-may-hold-a-password'.*-Primitive 'answer-file-may-hold-a-password'")

# Hive backup coverage: offline extraction pointers must be first-class leads/artifacts.
Chk 'registry hive backup section exists' (Has 'Registry hive backups \(readable SAM/SYSTEM/SECURITY = offline hash extraction\)')
Chk 'loose hive/NTDS copies are searched outside live config dir' (Has "'SAM','SYSTEM','SECURITY','NTDS\.dit'.*'\*\.hiv'.*'\*\.save'")
Chk 'readable SAM+SYSTEM hive backups are scored' (Has "Readable SAM \+ SYSTEM hive backups.*-Consumer 'hive-backup'.*-Primitive 'offline-hash-dump'")

"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
