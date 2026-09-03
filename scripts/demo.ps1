# demo.ps1 — проверка утилиты pamget «под ключ» на локальном стенде (Windows).
#
# Скрипт поднимает имитацию сервера PAM (fakepam), запрашивает у него все
# четыре типа записей и показывает поведение проверки TLS. Реальный сервер
# и настоящий токен не нужны.
#
# Запуск:  powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1

[CmdletBinding()]
param(
    [string]$PamHost = '127.0.0.1',
    [int]$Port       = 8443,
    [string]$Token   = $(if ($env:PAM_TOKEN) { $env:PAM_TOKEN } else { '00000000-0000-0000-0000-000000000001' }),
    [string]$Group   = '/Example/Common/Test/test_accounts'
)

$ErrorActionPreference = 'Stop'
$server = "https://${PamHost}:${Port}"
$root   = Split-Path -Parent $PSScriptRoot
$work   = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("pamdemo-" + [guid]::NewGuid())) -Force
$cert   = Join-Path $work 'fakepam.pem'

# Если рядом лежат собранные бинарники — используем их, иначе go run.
$useBinaries = (Test-Path (Join-Path $root 'pamget.exe')) -and (Test-Path (Join-Path $root 'fakepam.exe'))

function Invoke-Pamget {
    param([string[]]$PamArgs)
    if ($useBinaries) { & (Join-Path $root 'pamget.exe') @PamArgs }
    else { & go run (Join-Path $root 'cmd/pamget') @PamArgs }
}

Write-Host "==> Поднимаю тестовый сервер PAM на $server"
$serverArgs = @('-addr', "${PamHost}:${Port}", '-token', $Token, '-cert-out', $cert)
if ($useBinaries) {
    $proc = Start-Process -FilePath (Join-Path $root 'fakepam.exe') -ArgumentList $serverArgs -PassThru -WindowStyle Hidden
} else {
    $proc = Start-Process -FilePath 'go' -ArgumentList (@('run', (Join-Path $root 'cmd/fakepam')) + $serverArgs) -PassThru -WindowStyle Hidden
}

try {
    # Ждём появления файла сертификата — признак того, что сервер стартовал.
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path $cert) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path $cert)) { throw "Сервер не стартовал за 30 секунд" }

    $common = @('-server', $server, '-token', $Token, '-ca', $cert)

    Write-Host "`n==> Список записей, доступных токену"
    Invoke-Pamget ($common + @('-list'))

    foreach ($name in @('static_user_credentials', 'static_secret_data', 'static_ssl_certificate', 'static_ssh_key')) {
        Write-Host "`n--- $name"
        Invoke-Pamget ($common + @('-secret', "$Group/$name", '-comment', 'demo.ps1'))
    }

    Write-Host "`n--- весь ответ в JSON"
    Invoke-Pamget ($common + @('-secret', "$Group/static_ssh_key", '-json'))

    Write-Host "`n--- отдельное поле (passphrase)"
    Invoke-Pamget ($common + @('-secret', "$Group/static_ssh_key", '-field', 'passphrase'))

    Write-Host "`n--- проверка TLS включена: без доверенного CA запрос обязан упасть"
    Invoke-Pamget @('-server', $server, '-token', $Token, '-secret', "$Group/static_secret_data")
    if ($LASTEXITCODE -eq 0) { throw "самоподписанный сертификат был принят" }
    Write-Host "(ожидаемая ошибка выше — проверка сертификата работает)"

    Write-Host "`n--- тот же запрос с -insecure проходит"
    Invoke-Pamget @('-server', $server, '-token', $Token, '-insecure', '-secret', "$Group/static_secret_data")
    if ($LASTEXITCODE -ne 0) { throw "запрос с -insecure не прошёл" }

    Write-Host "`n--- неверный токен -> 401"
    Invoke-Pamget @('-server', $server, '-token', 'wrong-token', '-ca', $cert, '-secret', "$Group/static_secret_data")
    if ($LASTEXITCODE -eq 0) { throw "неверный токен был принят" }

    Write-Host "`n==> Все проверки пройдены"
}
finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
