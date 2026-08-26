# A9 config-discovery empty-template negative -- Known-Answer Tests.
# Imports the PRODUCTION $script:CfgSecretRe out of waldo.ps1 (no copy) and asserts that stock/empty templates are
# suppressed while genuinely cred-bearing config is surfaced. Mirrors Report-ConfigPath's decision.
# Run:  pwsh -NoProfile -File waldo/tests/a9_kat.ps1     (exit 0 = all PASS)
$ErrorActionPreference = 'Stop'
$ps1 = Join-Path (Split-Path $PSScriptRoot -Parent) 'waldo.ps1'
$line = Select-String -Path $ps1 -Pattern '^\$script:CfgSecretRe\s*=' | Select-Object -First 1
if (-not $line) { "FAIL  could not locate `$script:CfgSecretRe in waldo.ps1"; exit 1 }
Invoke-Expression $line.Line
$re = $script:CfgSecretRe
# decision mirrors Report-ConfigPath: inherent cred-bearing type by NAME, else content must match $re
function Is-Interesting([string]$name,[string]$text){
  if ($name -match '(?i)(\.udl$|connectionStrings.*\.config$)') { return $true }
  return ($text -match $re)
}
$pass=0;$fail=0
function Chk($desc,$got,$want){ if($got -eq $want){$script:pass++;"PASS  $desc"}else{$script:fail++;"FAIL  $desc (got $got want $want)"} }

# empty/stock ASP.NET Core template -> NEGATIVE
$emptyAppsettings = '{ "Logging": { "LogLevel": { "Default": "Information", "Microsoft.AspNetCore": "Warning" } }, "AllowedHosts": "*" }'
Chk 'empty appsettings.json (Logging+AllowedHosts only) -> suppressed' (Is-Interesting 'appsettings.json' $emptyAppsettings) $false
# stock launchSettings scaffolding -> NEGATIVE
$launch = '{ "profiles": { "MyApp": { "commandName": "Project", "applicationUrl": "https://localhost:5001" } } }'
Chk 'launchSettings.json scaffolding -> suppressed' (Is-Interesting 'launchSettings.json' $launch) $false
# assembly binding-redirect-only .config -> NEGATIVE
$bindingCfg = '<configuration><runtime><assemblyBinding><dependentAssembly><assemblyIdentity name="Newtonsoft.Json"/></dependentAssembly></assemblyBinding></runtime></configuration>'
Chk 'binding-redirect-only app.config -> suppressed' (Is-Interesting 'MyApp.exe.config' $bindingCfg) $false
# appsettings WITH a connection string -> POSITIVE
$csAppsettings = '{ "ConnectionStrings": { "Default": "Server=db;Database=app;User Id=sa;Password=S3cret!;" } }'
Chk 'appsettings.json with ConnectionStrings -> surfaced' (Is-Interesting 'appsettings.json' $csAppsettings) $true
# web.config with a connectionStrings section -> POSITIVE
$webCfg = '<configuration><connectionStrings><add name="db" connectionString="Data Source=.;Initial Catalog=app;User ID=sa;Password=p@ss"/></connectionStrings></configuration>'
Chk 'web.config with connectionString -> surfaced' (Is-Interesting 'web.config' $webCfg) $true
# .udl is inherently cred-bearing by type -> POSITIVE even if content unread
Chk '.udl inherent cred-bearing type -> surfaced' (Is-Interesting 'db.udl' '') $true
# connectionStrings.config by name -> POSITIVE
Chk 'connectionStrings.config by name -> surfaced' (Is-Interesting 'connectionStrings.config' '') $true
# a JSON with an API key -> POSITIVE
Chk 'appsettings with ApiKey -> surfaced' (Is-Interesting 'appsettings.Production.json' '{ "ApiKey": "abcd1234efgh" }') $true

"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
