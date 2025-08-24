# Windows-IR-Script
Windows용 사고 대응 Script입니다.

# 사용법
1.	관리자 권한으로 PowerShell 실행
2.	실행 명령어 : .\WinIR-Collector.ps1 -Case “사건번호” -OutputRoot “저장경로”
3.	.\tools\ 폴더에 Sysinternals 도구 넣기

# 실행 명령어
1. Set-ExecutionPolicy -Scope Process Bypass
2. Unblock-File .\WinIR-Collector.ps1
3. .\WinIR-Collector.ps1 -Case "2024-08-21" -OutputRoot "C:\IR"
