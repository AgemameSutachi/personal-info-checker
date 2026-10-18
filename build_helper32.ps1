<#
.SYNOPSIS
  Access 読み取り用の 32bit 補助 exe（access32_helper.exe）を PyInstaller で作る。

.DESCRIPTION
  32bit の venv（既定: ~/temp/venv/personal-info-checker-32）の PyInstaller で
  pii_checker/access32_helper.py を --onefile・コンソールの exe にし、dist_helper32/ へ置く。
  PyInstaller の作業フォルダ（build/）と .spec も dist_helper32/build/ の下に置き、
  プロジェクト直下を散らかさない。

  事前に 32bit venv へ入れておくもの:
    python -m pip install pyinstaller pyodbc pywin32
  （pyodbc・pywin32 は任意。無くても標準ライブラリだけの ctypes ODBC で動く exe になる）

.PARAMETER Python
  32bit の python.exe のパス。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File build_helper32.ps1
#>
param(
    [string]$Python = (Join-Path $env:USERPROFILE "temp\venv\personal-info-checker-32\Scripts\python.exe")
)

# Windows PowerShell 5.1 では "Stop" にすると、PyInstaller が標準エラーへ出すログだけで
# 停止してしまうため、外部コマンドは終了コードで判定する
$ErrorActionPreference = "Continue"

$ProjectRoot = $PSScriptRoot
$Source = Join-Path $ProjectRoot "pii_checker\access32_helper.py"
$DistDir = Join-Path $ProjectRoot "dist_helper32"
$WorkDir = Join-Path $DistDir "build"
$ExePath = Join-Path $DistDir "access32_helper.exe"

function Fail([string]$Message) {
    Write-Host "エラー: $Message" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $Python)) {
    Fail "32bit の Python が見つかりません: $Python`n  32bit 版の Python を入れ、<32bit の python.exe> -m venv `"$env:USERPROFILE\temp\venv\personal-info-checker-32`" で作るか、-Python で場所を指定してください。"
}
if (-not (Test-Path $Source)) {
    Fail "元のスクリプトが見つかりません: $Source"
}

# 32bit であることを確かめる（64bit で作ると Jet 4.0 / DAO.DBEngine.36 が使えない exe になる）
$Bits = (& $Python -c "import struct; print(struct.calcsize('P') * 8)").Trim()
if ($Bits -ne "32") {
    Fail "指定の Python は ${Bits}bit です。32bit の Python を指定してください: $Python"
}

& $Python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)"
if ($LASTEXITCODE -ne 0) {
    Fail "32bit の venv に PyInstaller がありません。$Python -m pip install pyinstaller を実行してください。"
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

Write-Host "ビルド開始: $Source -> $ExePath"
& $Python -m PyInstaller `
    --onefile `
    --console `
    --noconfirm `
    --clean `
    --name access32_helper `
    --distpath $DistDir `
    --workpath $WorkDir `
    --specpath $WorkDir `
    --exclude-module tkinter `
    --exclude-module unittest `
    --exclude-module pydoc `
    $Source
if ($LASTEXITCODE -ne 0) {
    Fail "PyInstaller が失敗しました（終了コード $LASTEXITCODE）。上の出力を確認してください。"
}
if (-not (Test-Path $ExePath)) {
    Fail "exe ができていません: $ExePath"
}

$SizeMB = [math]::Round((Get-Item $ExePath).Length / 1MB, 2)
Write-Host "完了: $ExePath（$SizeMB MB）" -ForegroundColor Green
