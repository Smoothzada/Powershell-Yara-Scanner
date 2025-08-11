$ErrorActionPreference = "SilentlyContinue"
Clear-Host

# --- Checar ADM ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "`n[ ! ] Este script precisa ser executado como administrador." -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit
}

# --- Variáveis ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$yaraExe = Join-Path $ScriptDir "yara64.exe"
$logPath = Join-Path $ScriptDir "yara_resultados.txt"
$detectLogPath = Join-Path $ScriptDir "DetectYara.txt"

# --- Entradas ---
$pathsTxt = Read-Host "Caminho do path.txt"
$pathsTxt = $pathsTxt.Trim('"').Trim("'")
$yaraRulePath = Read-Host "Caminho da yara Rule (.yar file)"
$yaraRulePath = $yaraRulePath.Trim('"').Trim("'")

# --- Validar entradas ---
if (-Not (Test-Path -LiteralPath $pathsTxt)) {
    Write-Host "[ ERRO ] Arquivo .txt não encontrado." -ForegroundColor Red
    exit
}
if (-Not (Test-Path -LiteralPath $yaraRulePath)) {
    Write-Host "[ ERRO ] Arquivo .yar não encontrado." -ForegroundColor Red
    exit
}

# Download yara64.exe
if (-Not (Test-Path -LiteralPath $yaraExe)) {
    Write-Host "yara64.exe não encontrado. Baixando..." -ForegroundColor Yellow
    $url = "https://github.com/VirusTotal/yara/releases/download/v4.5.4/yara-master-v4.5.4-win64.zip"
    $zipPath = Join-Path $ScriptDir "yara.zip"
    $extractPath = Join-Path $ScriptDir "yara_tmp"

    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }

    try {
        Invoke-WebRequest -Uri $url -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        $downloadedYara = Get-ChildItem -Path $extractPath -Recurse -Filter "yara64.exe" | Select-Object -First 1
        if ($downloadedYara) {
            Copy-Item $downloadedYara.FullName -Destination $yaraExe -Force
        } else {
            Write-Host "Não foi possível localizar yara64.exe após a extração." -ForegroundColor Red
            exit
        }
        Remove-Item $zipPath -Force
        Remove-Item $extractPath -Recurse -Force
    }
    catch {
        Write-Host "Erro ao baixar ou extrair yara: $_" -ForegroundColor Red
        exit
    }
}

# analisa o arquivo de texto
$filePaths = Get-Content -LiteralPath $pathsTxt | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
if ($filePaths.Count -eq 0) {
    Write-Host "[ AVISO ] Nenhum caminho válido encontrado no arquivo paths.txt." -ForegroundColor Yellow
    exit
}

# --- Criar logs ---
"" | Out-File -FilePath $logPath -Encoding utf8
"" | Out-File -FilePath $detectLogPath -Encoding utf8
"--- Início da análise: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ---`n" | Out-File -FilePath $logPath -Encoding utf8
"--- Resultados detectados: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ---`n" | Out-File -FilePath $detectLogPath -Encoding utf8


$results = @()

# progress
$host.privatedata.ProgressForegroundColor = "red"
$host.privatedata.ProgressBackgroundColor = "black"
$progressID = 1
$totalCount = $filePaths.Count
$count = 0
$stopwatch = [Diagnostics.Stopwatch]::StartNew()

foreach ($filePath in $filePaths) {
    $count++
    $progress = [int]($count / $totalCount * 100)
    Write-Progress -Activity "Analisando arquivos com YARA..." -Status "$progress% completo" -PercentComplete $progress -Id $progressID

    $filePathClean = $filePath.Trim() -replace '[\u200B]', ''

    if (-Not (Test-Path -LiteralPath $filePathClean)) {
        "[ERRO] $(Get-Date -Format 'HH:mm:ss') | Arquivo não encontrado: $filePathClean" | Out-File -FilePath $logPath -Append -Encoding utf8
        $results += [PSCustomObject]@{ Filename = Split-Path $filePathClean -Leaf; Filepath = $filePathClean; Detect = "Error"; YaraRule = ""; Erro = "Arquivo não encontrado" }
        continue
    }

    $output = & $yaraExe $yaraRulePath "`"$filePathClean`"" 2>$null
    $exitcode = $LASTEXITCODE

    if ($exitcode -eq 0 -and $output) {
        $detectedRules = @()
        foreach ($line in $output) {
            if ($line -match '^\S+') {
                $ruleName = $line.Split()[0]
                if (-not $detectedRules.Contains($ruleName)) { $detectedRules += $ruleName }
            }
        }
        $rulesFormatted = ($detectedRules | ForEach-Object { "[ $_ ]" }) -join ' '
        "[DETECTADO] $(Get-Date -Format 'HH:mm:ss') | $filePathClean | $rulesFormatted" | Out-File -FilePath $logPath -Append -Encoding utf8
        "[DETECTADO] $(Get-Date -Format 'HH:mm:ss') | $filePathClean | $rulesFormatted" | Out-File -FilePath $detectLogPath -Append -Encoding utf8
        $results += [PSCustomObject]@{ Filename = Split-Path $filePathClean -Leaf; Filepath = $filePathClean; Detect = "Yes"; YaraRule = ($detectedRules -join ', '); Erro = "" }
    }
    elseif ($exitcode -in 0,1) {
        "[LIMPO] $(Get-Date -Format 'HH:mm:ss') | $filePathClean" | Out-File -FilePath $logPath -Append -Encoding utf8
        $results += [PSCustomObject]@{ Filename = Split-Path $filePathClean -Leaf; Filepath = $filePathClean; Detect = "No"; YaraRule = ""; Erro = "" }
    }
    else {
        "[ERRO] $(Get-Date -Format 'HH:mm:ss') | $filePathClean | Código: $exitcode" | Out-File -FilePath $logPath -Append -Encoding utf8
        $results += [PSCustomObject]@{ Filename = Split-Path $filePathClean -Leaf; Filepath = $filePathClean; Detect = "Error"; YaraRule = ""; Erro = "Código: $exitcode" }
    }
}

$stopwatch.Stop()

# --- Mostrar GridView ---
if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    $results | Out-GridView -Title "Resultados YARA (Yes / No / Error)" -PassThru
}

Write-Host ""
Write-Host "Tempo total: $($stopwatch.Elapsed.ToString())" -ForegroundColor Yellow
Write-Host "Salvo em: $logPath" -ForegroundColor Yellow
Write-Host "Detect salvo em $detectLogPath" -ForegroundColor Red