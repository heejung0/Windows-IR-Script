<# 
.SYNOPSIS
  Windows Incident Response Collector (volatile-first)
.DESCRIPTION
  - 관리자 권한 필요
  - 순정 명령 우선, Sysinternals/기타 도구는 있으면 자동 활용
  - 수집 후 ZIP 압축 + SHA256 해시
.PARAMETER Case
  케이스/사건명 (폴더 이름에 사용)
.PARAMETER OutputRoot
  결과 저장 루트 경로 (기본: C:\IR)
.PARAMETER Hours
  최근 이벤트 로그 조회 시간 (기본: 48)
.PARAMETER DumpDNSCache
  ipconfig /displaydns 실행 여부 (기본: $true)
.PARAMETER TryMemoryDumpWithWinPMEM
  .\tools\winpmem.exe 있으면 메모리 덤프 시도 (기본: $false)
#>

[CmdletBinding()]
param(
  [string]$Case = "$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
  [string]$OutputRoot = "C:\IR",
  [int]$Hours = 48,
  [bool]$DumpDNSCache = $true,
  [bool]$TryMemoryDumpWithWinPMEM = $false
)

#-------------------- Preflight --------------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "관리자 권한 PowerShell로 다시 실행하세요."
    exit 1
  }
}
Assert-Admin

$CaseDir = Join-Path $OutputRoot $Case
$ToolsDir = Join-Path $PSScriptRoot "tools"
$null = New-Item -Type Directory -Force -Path $CaseDir | Out-Null
$LogDir = Join-Path $CaseDir "00_logs"
$null = New-Item -Type Directory -Force -Path $LogDir | Out-Null

# 통합 로그
$Transcript = Join-Path $LogDir "transcript.txt"
Start-Transcript -Path $Transcript -Force | Out-Null

# 공용 헬퍼
function Save-Cmd {
  param([string]$Command, [string]$OutFile, [switch]$NoEncoding)
  try {
    if ($NoEncoding) {
      cmd.exe /c "$Command" 2>&1 | Out-File -FilePath $OutFile -Force
    } else {
      cmd.exe /c "$Command" 2>&1 | Out-File -FilePath $OutFile -Force -Encoding UTF8
    }
  } catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutFile -Force
  }
}
function Save-PS {
  param([scriptblock]$Script, [string]$OutFile)
  try {
    & $Script 2>&1 | Out-File -FilePath $OutFile -Force -Encoding UTF8
  } catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutFile -Force
  }
}
function Path-OrNull([string]$exe) {
  $p = Get-Command $exe -ErrorAction SilentlyContinue
  if ($p) { return $p.Source }
  $local = Join-Path $ToolsDir $exe
  if (Test-Path $local) { return $local }
  return $null
}
function Write-Section($name) { Write-Host "==== $name ====" }

# 폴더 구성
$Folders = @(
  "01_time", "02_memory", "03_net", "04_sessions", "05_process", "06_handles_modules",
  "07_services_drivers", "08_schtasks_startup", "09_registry_exports", "10_users_groups",
  "11_persistence", "12_evtx", "13_filesystem", "14_systeminfo", "15_hashes"
)
foreach ($f in $Folders) { New-Item -Type Directory -Force -Path (Join-Path $CaseDir $f) | Out-Null }

# 도구 경로
$tool = @{
  psinfo   = Path-OrNull "psinfo.exe"
  pslist   = Path-OrNull "pslist.exe"
  handle   = Path-OrNull "handle.exe"
  listdlls = Path-OrNull "listdlls.exe"
  autorunsc= Path-OrNull "autorunsc.exe"
  sigcheck = Path-OrNull "sigcheck.exe"
  tcpvcon  = Path-OrNull "tcpvcon.exe"
  fport    = Path-OrNull "fport.exe"
  winpmem  = Path-OrNull "winpmem.exe"
}

# 수집 시작 시각(증거 시각)
$StartIso = Get-Date -AsUTC -Format "yyyy-MM-ddTHH:mm:ssZ"
Set-Content -Path (Join-Path $CaseDir "collection_meta.txt") -Value @(
  "case=$Case"
  "started_utc=$StartIso"
  "hostname=$(hostname)"
  "user=$env:USERNAME"
  "timezone=$(Get-TimeZone).Id"
) -Encoding UTF8

#-------------------- 1) TIME (가장 먼저) --------------------
Write-Section "TIME"
$T = Join-Path $CaseDir "01_time"
Get-Date -Format "yyyy-MM-dd HH:mm:ss.ffff zzz" | Out-File (Join-Path $T "local_time.txt") -Encoding UTF8
(Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.ffff 'UTC'") | Out-File (Join-Path $T "utc_time.txt") -Encoding UTF8
Save-PS { w32tm /tz } (Join-Path $T "timezone.txt")
Save-PS { Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime,InstallDate,CSName,Version,BuildNumber | Format-List } (Join-Path $T "boot_times.txt")

#-------------------- 2) (선택) MEMORY DUMP (가장 휘발성) --------------------
Write-Section "MEMORY"
$M = Join-Path $CaseDir "02_memory"
if ($TryMemoryDumpWithWinPMEM -and $tool.winpmem) {
  $memOut = Join-Path $M "memory.raw"
  Save-Cmd "`"$($tool.winpmem)`" `"$memOut`"" (Join-Path $M "winpmem_log.txt")
} else {
  "winpmem.exe 미사용 또는 옵션 미설정 - 스킵" | Out-File (Join-Path $M "memory_dump_skipped.txt")
}

#-------------------- 3) NETWORK (연결 상태가 금방 변함) --------------------
Write-Section "NETWORK"
$N = Join-Path $CaseDir "03_net"
Save-Cmd "ipconfig /all" (Join-Path $N "ipconfig_all.txt")
Save-Cmd "arp -a"        (Join-Path $N "arp.txt")
Save-Cmd "route print"   (Join-Path $N "routes.txt")
Save-PS { Get-NetIPConfiguration } (Join-Path $N "Get-NetIPConfiguration.txt")
Save-PS { Get-NetAdapter -Physical } (Join-Path $N "Get-NetAdapter.txt")
Save-PS { Get-NetRoute | Sort-Object -Property DestinationPrefix } (Join-Path $N "Get-NetRoute.txt")

# 연결/포트
if ($tool.tcpvcon) {
  Save-Cmd "`"$($tool.tcpvcon)`" -acn" (Join-Path $N "tcpvcon_acn.txt")
} else {
  Save-PS { 
    Get-NetTCPConnection -ErrorAction SilentlyContinue | 
      Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess |
      Sort-Object LocalPort
  } (Join-Path $N "Get-NetTCPConnection.txt")
  Save-Cmd "netstat -nao" (Join-Path $N "netstat_nao.txt")
}

if ($DumpDNSCache) { Save-Cmd "ipconfig /displaydns" (Join-Path $N "dns_cache.txt") }
Save-Cmd "netsh wlan show all" (Join-Path $N "wlan_profiles.txt")
Save-Cmd "netsh advfirewall show allprofiles" (Join-Path $N "firewall_profiles.txt")
Save-Cmd "netsh advfirewall firewall show rule name=all" (Join-Path $N "firewall_rules.txt")
Save-Cmd "netsh winhttp show proxy" (Join-Path $N "winhttp_proxy.txt")

#-------------------- 4) SESSIONS / LOGONS --------------------
Write-Section "SESSIONS"
$S = Join-Path $CaseDir "04_sessions"
Save-Cmd "query user" (Join-Path $S "quser.txt")
Save-Cmd "qwinsta"    (Join-Path $S "qwinsta.txt")
Save-Cmd "net session" (Join-Path $S "net_session.txt")
Save-PS { 
  Get-CimInstance Win32_LoggedOnUser |
    ForEach-Object {
      [PSCustomObject]@{
        Domain   = $_.Antecedent.PSObject.Properties['Domain'].Value
        User     = $_.Antecedent.PSObject.Properties['Name'].Value
        LogonId  = $_.Dependent.PSObject.Properties['LogonId'].Value
      }
    } | Sort-Object User,LogonId
} (Join-Path $S "Win32_LoggedOnUser.txt")

#-------------------- 5) PROCESSES (프로세스 트리/모듈/사인/해시) --------------------
Write-Section "PROCESSES"
$PDir = Join-Path $CaseDir "05_process"
Save-PS { Get-Process | Sort-Object Id | Format-Table -AutoSize * } (Join-Path $PDir "Get-Process_full.txt")
Save-PS { Get-Process | Select-Object Id,ProcessName,Path,StartTime,CPU,PM,WS,VM | Sort-Object Id } (Join-Path $PDir "Get-Process_brief.txt")

# Parent/Child 트리
Save-PS {
  Get-CimInstance Win32_Process | 
    Select-Object ProcessId,ParentProcessId,CreationDate,Name,ExecutablePath,CommandLine |
    Sort-Object ParentProcessId,ProcessId
} (Join-Path $PDir "process_tree_wmi.txt")

# 실행중 바이너리 해시 (존재하는 Path만)
$HashOut = Join-Path $PDir "process_image_hashes.csv"
$procs = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and (Test-Path $_.ExecutablePath) }
$hashList = foreach ($p in $procs) {
  try {
    $h = Get-FileHash -Algorithm SHA256 -LiteralPath $p.ExecutablePath -ErrorAction Stop
    [PSCustomObject]@{
      PID = $p.ProcessId; Name=$p.Name; Path=$p.ExecutablePath; SHA256=$h.Hash
    }
  } catch {
    [PSCustomObject]@{ PID=$p.ProcessId; Name=$p.Name; Path=$p.ExecutablePath; SHA256="ERROR" }
  }
}
$hashList | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $HashOut

#-------------------- 6) HANDLES / MODULES (Sysinternals가 있으면) --------------------
Write-Section "HANDLES & MODULES"
$HM = Join-Path $CaseDir "06_handles_modules"
if ($tool.handle)   { Save-Cmd "`"$($tool.handle)`" -a" (Join-Path $HM "handle_all.txt") }
if ($tool.listdlls) { Save-Cmd "`"$($tool.listdlls)`" -u" (Join-Path $HM "listdlls_user_only.txt") }

#-------------------- 7) SERVICES / DRIVERS --------------------
Write-Section "SERVICES/DRIVERS"
$SD = Join-Path $CaseDir "07_services_drivers"
Save-PS { Get-Service | Sort-Object Status,DisplayName | Format-Table -AutoSize * } (Join-Path $SD "Get-Service.txt")
Save-Cmd "sc query type= service state= all" (Join-Path $SD "sc_query_services.txt")
Save-Cmd "driverquery /v" (Join-Path $SD "driverquery_v.txt")
Save-Cmd "fltmc" (Join-Path $SD "fltmc.txt")

#-------------------- 8) SCHEDULED TASKS / STARTUP --------------------
Write-Section "TASKS & STARTUP"
$TS = Join-Path $CaseDir "08_schtasks_startup"
Save-Cmd "schtasks /query /fo list /v" (Join-Path $TS "schtasks_list_v.txt")

# autoruns (있으면 강력)
if ($tool.autorunsc) {
  Save-Cmd "`"$($tool.autorunsc)`" -a * -ct -m -nobanner -accepteula -h -s -vt -csv `"$TS\autoruns.csv`"" (Join-Path $TS "autoruns_log.txt")
} else {
  # 레지스트리 Run 키 덤프
  reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"        (Join-Path $TS "Run_HKLM.reg") /y | Out-Null
  reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"        (Join-Path $TS "Run_HKCU.reg") /y | Out-Null
  reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"    (Join-Path $TS "RunOnce_HKLM.reg") /y | Out-Null
  reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"    (Join-Path $TS "RunOnce_HKCU.reg") /y | Out-Null
  # Startup 폴더 목록
  Save-PS { Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue } (Join-Path $TS "Startup_AllUsers.txt")
  Save-PS { Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue } (Join-Path $TS "Startup_CurrentUser.txt")
}

#-------------------- 9) REGISTRY SNAPSHOTS (핵심 키 내보내기) --------------------
Write-Section "REGISTRY EXPORTS"
$RG = Join-Path $CaseDir "09_registry_exports"
$regKeys = @(
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM\SYSTEM\CurrentControlSet\Services',
  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
  'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager',
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
  'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
)
foreach ($k in $regKeys) {
  $safe = ($k -replace '[\\/:*?"<>|]', '_')
  Save-Cmd "reg export `"$k`" `"$RG\$safe.reg`" /y" (Join-Path $RG "export_$safe.log")
}

#-------------------- 10) USERS / GROUPS --------------------
Write-Section "USERS/GROUPS"
$UG = Join-Path $CaseDir "10_users_groups"
Save-Cmd "net user" (Join-Path $UG "net_user.txt")
Save-Cmd "net localgroup" (Join-Path $UG "net_localgroup.txt")
Save-Cmd "net localgroup administrators" (Join-Path $UG "net_localgroup_administrators.txt")
Save-Cmd "whoami /all" (Join-Path $UG "whoami_all.txt")

# 도메인인 경우
Save-Cmd "nltest /dsgetdc:." (Join-Path $UG "domain_info.txt")

#-------------------- 11) PERSISTENCE (WMI, IFEO, AppInit 등) --------------------
Write-Section "PERSISTENCE"
$PE = Join-Path $CaseDir "11_persistence"
# WMI 영속성
Save-PS {
  $ns = "root\subscription"
  Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue
} (Join-Path $PE "WMI_EventFilter.txt")
Save-PS {
  $ns = "root\subscription"
  Get-WmiObject -Namespace $ns -Class __EventConsumer -ErrorAction SilentlyContinue
} (Join-Path $PE "WMI_EventConsumer.txt")
Save-PS {
  $ns = "root\subscription"
  Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
} (Join-Path $PE "WMI_Bindings.txt")

# IFEO
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s | Out-File (Join-Path $PE "IFEO.txt") -Encoding UTF8

# AppInit_DLLs / LSA Providers
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs | Out-File (Join-Path $PE "AppInit_DLLs.txt") -Encoding UTF8
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" | Out-File (Join-Path $PE "LSA.txt") -Encoding UTF8

#-------------------- 12) EVENT LOGS (최근 $Hours 시간) --------------------
Write-Section "EVENT LOGS"
$EV = Join-Path $CaseDir "12_evtx"
$Since = (Get-Date).AddHours(-$Hours)

# 보안 관련: 로그온/계정/권한
$secIds = 4624,4625,4634,4648,4672,4688,4697,4720,4722,4723,4724,4728,4732,4756,4768,4769,4776,5140,5145
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Since; Id=$secIds} -ErrorAction SilentlyContinue |
  Export-Clixml (Join-Path $EV "Security_${Hours}h.xml")

# 시스템/응용/PowerShell
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Since} -ErrorAction SilentlyContinue |
  Export-Clixml (Join-Path $EV "System_${Hours}h.xml")
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$Since} -ErrorAction SilentlyContinue |
  Export-Clixml (Join-Path $EV "Application_${Hours}h.xml")
foreach ($pslog in @('Microsoft-Windows-PowerShell/Operational','Windows PowerShell')) {
  try {
    Get-WinEvent -LogName $pslog -ErrorAction Stop -MaxEvents 1 | Out-Null
    Get-WinEvent -FilterHashtable @{LogName=$pslog; StartTime=$Since} |
      Export-Clixml (Join-Path $EV ("{0}_{1}h.xml" -f ($pslog -replace '[\\/]', '_'), $Hours))
  } catch {}
}

#-------------------- 13) FILESYSTEM ARTIFACTS (간접지표) --------------------
Write-Section "FILESYSTEM"
$FS = Join-Path $CaseDir "13_filesystem"
# Prefetch 디렉터리 목록(있는 OS에서)
$pfDir = "$env:WINDIR\Prefetch"
if (Test-Path $pfDir) {
  Get-ChildItem $pfDir -Force -ErrorAction SilentlyContinue |
    Select-Object Name,Length,CreationTime,LastWriteTime |
    Sort-Object LastWriteTime -Descending |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $FS "prefetch_listing.csv")
}
# 최근 파일(사용자 프로필)
Get-ChildItem "$env:USERPROFILE\Recent" -ErrorAction SilentlyContinue |
  Select-Object Name,LastWriteTime,CreationTime |
  Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $FS "recent_items.csv")

# USBSTOR 인상
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s | Out-File (Join-Path $FS "usbstor.txt") -Encoding UTF8

#-------------------- 14) SYSTEM INFO / 소프트웨어 --------------------
Write-Section "SYSTEMINFO"
$SI = Join-Path $CaseDir "14_systeminfo"
Save-Cmd "systeminfo" (Join-Path $SI "systeminfo.txt")
if ($tool.psinfo) {
  Save-Cmd "`"$($tool.psinfo)`" -h -s -d" (Join-Path $SI "psinfo_hsd.txt")
}
# 설치 프로그램 (레지스트리)
Save-PS {
  $paths = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  foreach ($p in $paths) {
    Get-ChildItem $p -ErrorAction SilentlyContinue |
      ForEach-Object { Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue } |
      Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object DisplayName
  }
} (Join-Path $SI "installed_programs.txt")

#-------------------- 15) HASHES (수집 산출물 무결성) --------------------
Write-Section "HASHES"
$HS = Join-Path $CaseDir "15_hashes"
# 수집 디렉터리 내 파일 전체 SHA256
$AllFiles = Get-ChildItem $CaseDir -Recurse -File -ErrorAction SilentlyContinue
$hashCsv = Join-Path $HS "collection_file_hashes.csv"
$AllFiles | ForEach-Object {
  try {
    $h = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
    [PSCustomObject]@{ Path=$_.FullName; Size=$_.Length; SHA256=$h.Hash }
  } catch {
    [PSCustomObject]@{ Path=$_.FullName; Size=$_.Length; SHA256="ERROR" }
  }
} | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $hashCsv

#-------------------- FINAL: ZIP & DIGEST --------------------
Write-Section "ARCHIVE"
$ZipPath = Join-Path $OutputRoot "$Case.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path $CaseDir -DestinationPath $ZipPath
$ZipHash = Get-FileHash -Algorithm SHA256 $ZipPath
$ZipHash.Hash | Out-File (Join-Path $CaseDir "archive_sha256.txt") -Encoding ascii

Stop-Transcript | Out-Null

Write-Host ""
Write-Host "수집 완료"
Write-Host " - 결과 폴더: $CaseDir"
Write-Host " - ZIP: $ZipPath"
Write-Host " - ZIP SHA256: $($ZipHash.Hash)"
