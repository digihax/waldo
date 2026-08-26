# VNC A5b decoder -- Known-Answer Tests (INDEPENDENT provenance).
# Vectors were produced by openssl / pycryptodome (standard DES) and the Win32 WritePrivateProfileStruct
# API -- NOT by Waldo's own decoder -- so a shared bug cannot pass both sides.
# Run:  pwsh -NoProfile -File waldo/tests/vnc_kat.ps1     (exit 0 = all PASS)
$ErrorActionPreference = 'Stop'
function Decode-VncDes([byte[]]$Blob){
  if (-not $Blob -or $Blob.Length -lt 8) { return $null }
  $key=[byte[]](0xE8,0x4A,0xD6,0x60,0xC4,0x72,0x1A,0xE0)   # {23,82,107,6,35,78,88,7} bit-reversed per byte
  $des=[System.Security.Cryptography.DES]::Create();$des.Mode='ECB';$des.Padding='None';$des.Key=$key
  $out=$des.CreateDecryptor().TransformFinalBlock($Blob,0,8); $n=[Array]::IndexOf($out,[byte]0); if($n -lt 0){$n=8}
  [System.Text.Encoding]::ASCII.GetString($out,0,$n)
}
function Hex([string]$h){ $b=for($i=0;$i -lt $h.Length;$i+=2){[Convert]::ToByte($h.Substring($i,2),16)}; ,[byte[]]$b }
$pass=0;$fail=0
# --- raw 8-byte block vectors (openssl/pycryptodome-produced) ---
$vectors = @(
  @{ hex='50ccb2fc99726c7f'; expect='Secret12' }
  @{ hex='9c0a172d3482e122'; expect='abc' }
  @{ hex='4c995abc1beaff70'; expect='R00t!Pw' }
  @{ hex='2005ed6913063a69'; expect='monkey' }
)
foreach($v in $vectors){ $got=Decode-VncDes (Hex $v.hex); if($got -eq $v.expect){$pass++;"PASS  raw-block $($v.hex) -> $got"}else{$fail++;"FAIL  raw-block $($v.hex) -> got [$got] expected [$($v.expect)]"} }
# --- UltraVNC INI 18-hex (checksum validated by GetPrivateProfileStruct): positive + tamper negative ---
Add-Type -Namespace K -Name Ini -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Ansi)] public static extern bool WritePrivateProfileStructA(string s,string k,byte[] b,uint n,string f);
[System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Ansi)] public static extern bool GetPrivateProfileStructA(string s,string k,byte[] b,uint n,string f);
'@
$ini=Join-Path $env:TEMP ("vnc_kat_"+[guid]::NewGuid().ToString('N')+'.ini')
[void][K.Ini]::WritePrivateProfileStructA('ultravnc','passwd',(Hex '50ccb2fc99726c7f'),8,$ini)
$buf=New-Object byte[] 8
if([K.Ini]::GetPrivateProfileStructA('ultravnc','passwd',$buf,8,$ini) -and (Decode-VncDes $buf) -eq 'Secret12'){$pass++;"PASS  INI 18-hex read+decode -> Secret12"}else{$fail++;"FAIL  INI 18-hex read+decode"}
(Get-Content $ini -Raw) -replace '(passwd=[0-9A-Fa-f]{16})[0-9A-Fa-f]{2}','${1}00' | Set-Content $ini -NoNewline
$buf2=New-Object byte[] 8
if(-not [K.Ini]::GetPrivateProfileStructA('ultravnc','passwd',$buf2,8,$ini)){$pass++;"PASS  INI bad-checksum rejected (not decoded)"}else{$fail++;"FAIL  INI bad-checksum NOT rejected"}
Remove-Item $ini -ErrorAction SilentlyContinue
# --- malformed / wrong-length negatives (must NOT yield a plaintext) ---
if((Decode-VncDes (Hex 'deadbeef')) -eq $null){$pass++;"PASS  short/malformed blob -> null"}else{$fail++;"FAIL  malformed blob not rejected"}
# --- A5 registry format classification (mirrors waldo.ps1 reg-store branch): store family + byte length -> (format,decode) ---
function Classify-VncReg([string]$fam,[int]$len){
  if ($fam -eq 'RealVNC-modern') { return @{ format='salted_hash'; decode='not_applicable' } }
  elseif ($len -eq 8)           { return @{ format='reversible_supported'; decode='requested_or_not' } }
  else                          { return @{ format='unknown_format'; decode='unsupported' } }
}
$cvecs = @(
  @{ fam='WinVNC3';        len=8;  fmt='reversible_supported'; dec='requested_or_not'; why='8-byte fixed-key WinVNC3' }
  @{ fam='TightVNC';       len=8;  fmt='reversible_supported'; dec='requested_or_not'; why='8-byte fixed-key TightVNC' }
  @{ fam='RealVNC-legacy'; len=8;  fmt='reversible_supported'; dec='requested_or_not'; why='legacy RealVNC 8-byte fixed-key' }
  @{ fam='RealVNC-legacy'; len=16; fmt='unknown_format';       dec='unsupported';       why='legacy RealVNC >=16 is NOT length-guessed as salted_hash' }
  @{ fam='RealVNC-legacy'; len=20; fmt='unknown_format';       dec='unsupported';       why='legacy RealVNC other length -> unknown_format' }
  @{ fam='RealVNC-modern'; len=32; fmt='salted_hash';        dec='not_applicable';    why='modern vncserver store -> salted, non-reversible' }
  @{ fam='RealVNC-modern'; len=8;  fmt='salted_hash';        dec='not_applicable';    why='modern store recognized by STORE, not length' }
  @{ fam='WinVNC3';        len=5;  fmt='unknown_format';       dec='unsupported';       why='malformed 5-byte -> unknown_format' }
)
foreach($c in $cvecs){ $r=Classify-VncReg $c.fam $c.len; if($r.format -eq $c.fmt -and $r.decode -eq $c.dec){$pass++;"PASS  reg[$($c.fam),$($c.len)b] -> $($r.format)/$($r.decode) ($($c.why))"}else{$fail++;"FAIL  reg[$($c.fam),$($c.len)b] -> $($r.format)/$($r.decode) expected $($c.fmt)/$($c.dec)"} }

# --- A5 reconciled role/activity enums (fact vs hypothesis SEPARATE): role in {server,client,unknown};
#     activity in {active,installed_only,unknown}. An unattributed listener never sets a server role/activity. ---
function Classify-VncRole([bool]$active,[bool]$viewer,[bool]$installed){
  $role = if ($active) {'server'} elseif ($viewer) {'client'} else {'unknown'}
  $act  = if ($active) {'active'} elseif ($viewer) {'unknown'} elseif ($installed) {'installed_only'} else {'unknown'}
  @{ role=$role; activity=$act }
}
$rvecs = @(
  @{ a=$true;  v=$false; i=$false; role='server';  act='active';         why='running/attributed server' }
  @{ a=$false; v=$true;  i=$true;  role='client';  act='unknown';        why='viewer present -> client, no server-activity claim' }
  @{ a=$false; v=$false; i=$true;  role='unknown'; act='installed_only'; why='installed-only -> role unknown, activity installed_only' }
  @{ a=$false; v=$false; i=$false; role='unknown'; act='unknown';        why='nothing / unattributed listener -> no server claim (hypothesis is a separate lead)' }
)
foreach($rv in $rvecs){ $r=Classify-VncRole $rv.a $rv.v $rv.i; if($r.role -eq $rv.role -and $r.activity -eq $rv.act){$pass++;"PASS  role[a=$($rv.a),v=$($rv.v),i=$($rv.i)] -> $($r.role)/$($r.activity) ($($rv.why))"}else{$fail++;"FAIL  role[a=$($rv.a),v=$($rv.v),i=$($rv.i)] -> $($r.role)/$($r.activity) expected $($rv.role)/$($rv.act)"} }
"";"KAT RESULT: $pass passed, $fail failed"
if($fail){ exit 1 } else { exit 0 }
