function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    # Si no es administrador, reiniciar como administrador
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    return  # Se usa 'return' para evitar que el script se detenga
}

# Selección de días para restaurar el archivo termsrv.dll
$selectedDays = Read-Host "Seleccione el número de días para restaurar el archivo termsrv.dll (30, 60, 90, 180, 270, 365)"
$validDays = @('30', '60', '90', '180', '270', '365')

# Validación de la entrada
if ($validDays -contains $selectedDays) {
    Write-Host "Seleccionado: $selectedDays días" -ForegroundColor Green
} else {
    Write-Host "Opción no válida. Saliendo del script..." -ForegroundColor Red
    Exit
}


# Stop RDP service, make a backup of the termsrv.dllfile and change the permissions 
Stop-Service UmRdpService -Force
Stop-Service TermService -Force
$termsrv_dll_acl = Get-Acl c:\windows\system32\termsrv.dll
Copy-Item c:\windows\system32\termsrv.dll c:\windows\system32\termsrv.dll.copy
takeown /f c:\windows\system32\termsrv.dll
$new_termsrv_dll_owner = (Get-Acl c:\windows\system32\termsrv.dll).owner
cmd /c "icacls c:\windows\system32\termsrv.dll /Grant $($new_termsrv_dll_owner):F /C"
# search for a pattern in termsrv.dll file 
$dll_as_bytes = Get-Content c:\windows\system32\termsrv.dll -Raw -Encoding byte
$dll_as_text = $dll_as_bytes.forEach('ToString', 'X2') -join ' '
$patternregex = ([regex]'39 81 3C 06 00 00(\s\S\S){6}')
$patch = 'B8 00 01 00 00 89 81 38 06 00 00 90'
$checkPattern=Select-String -Pattern $patternregex -InputObject $dll_as_text
If ($checkPattern -ne $null) {
    $dll_as_text_replaced = $dll_as_text -replace $patternregex, $patch
}
Elseif (Select-String -Pattern $patch -InputObject $dll_as_text) {
    Write-Output 'The termsrv.dll file is already patched, exiting'
    Exit
}
else { 
    Write-Output "Pattern not found "
}
# patching termsrv.dll
[byte[]] $dll_as_bytes_replaced = -split $dll_as_text_replaced -replace '^', '0x'
Set-Content c:\windows\system32\termsrv.dll.patched -Encoding Byte -Value $dll_as_bytes_replaced
# comparing two files 
fc.exe /b c:\windows\system32\termsrv.dll.patched c:\windows\system32\termsrv.dll
# replacing the original termsrv.dll file 
Copy-Item c:\windows\system32\termsrv.dll.patched c:\windows\system32\termsrv.dll -Force
Set-Acl c:\windows\system32\termsrv.dll $termsrv_dll_acl
Start-Service UmRdpService
Start-Service TermService


# Ruta del archivo de restauración
$restoreScriptPath = "C:\Windows\System32\Restore-TermSrv.ps1"

# Contenido del script de restauración
$restoreScriptContent = @'
# Verificar si el script se está ejecutando como administrador
function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    # Si no es administrador, reiniciar como administrador
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    return  # Se usa 'return' para evitar que el script se detenga
}

# Detener servicios RDP
Stop-ScheduledTask -TaskName $taskName

Stop-Service UmRdpService -Force
Stop-Service TermService -Force

# Verificar si existe una copia de seguridad
if (Test-Path "C:\Windows\System32\termsrv.dll.copy") {
    # Restaurar el archivo original
    Copy-Item -Path "C:\Windows\System32\termsrv.dll.copy" -Destination "C:\Windows\System32\termsrv.dll" -Force
    
    # Restaurar permisos originales
    $original_acl = Get-Acl "C:\Windows\System32\termsrv.dll.copy"
    Set-Acl -Path "C:\Windows\System32\termsrv.dll" -AclObject $original_acl
    
    # Eliminar archivos temporales creados por el script de parcheo
    Remove-Item "C:\Windows\System32\termsrv.dll.copy" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\System32\termsrv.dll.patched" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\System32\Restore-TermSrv.ps1" -Force -ErrorAction SilentlyContinue

    Write-Output "Restauración completada. Se ha restaurado el archivo original."
} else {
    Write-Output "No se encontró una copia de seguridad. No se puede restaurar el archivo original."
}

# Iniciar servicios RDP
Start-Service UmRdpService
Start-Service TermService

# Verificar si la tarea ya existe
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Write-Host "La tarea programada '$taskName' ya existe. Eliminándola..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
'@

# Crear el archivo de restauración usando Out-File
$restoreScriptContent | Out-File -FilePath $restoreScriptPath -Encoding UTF8 -Force

# Crear una tarea programada para ejecutar Restore-TermSrv.ps1 cada X días según la selección del usuario
#$TaskName = "Restore_TermSrv"
#$TaskDescription = "Restaura el archivo original termsrv.dll cada $selectedDays días"
#$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'irm https://raw.githubusercontent.com/mggons93/Mggons-RDP/refs/heads/main/Restore-TermSrv.ps1 | iex'`""
#$TaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval $selectedDays -At 3:00AM
#$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
#$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
#Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings -Force

# Crear una tarea programada para ejecutar Restore-TermSrv.ps1 cada X días según la selección del usuario
$TaskName = "Restore_TermSrv"
$TaskDescription = "Restaura el archivo original termsrv.dll cada $selectedDays días"
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/mggons93/Mggons-RDP/refs/heads/main/Restore-TermSrv.ps1 | iex`""
$TaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval $selectedDays -At 3:00AM
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden:$false

Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings -Force
