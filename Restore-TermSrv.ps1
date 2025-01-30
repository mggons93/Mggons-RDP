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
