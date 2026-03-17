$ProjectRoot = Get-Location
$PythonExecutable = "$ProjectRoot\.venv\Scripts\python.exe"
$BridgeScript = "$ProjectRoot\ai_agent\bridge.py"
$Port = 5001

Write-Host "🛡️ Starting AegisAI Integrated System..." -ForegroundColor Cyan

# 1. Start Python Bridge
Write-Host "🚀 Launching AI Inference Engine..." -ForegroundColor Yellow
$BridgeProcess = Start-Process -FilePath $PythonExecutable -ArgumentList "bridge.py" -WorkingDirectory "$ProjectRoot\ai_agent" -NoNewWindow -PassThru -RedirectStandardOutput "$ProjectRoot\ai_agent\bridge.log" -RedirectStandardError "$ProjectRoot\ai_agent\bridge.log"

# 2. Wait for Bridge
Write-Host "⏳ Waiting for models to load (this may take a few seconds)..." -ForegroundColor Gray
$MaxRetries = 60
$RetryCount = 0
$Ready = $false

while (-not $Ready -and $RetryCount -lt $MaxRetries) {
    try {
        $Response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -ErrorAction SilentlyContinue
        if ($Response.StatusCode -eq 200) {
            $Ready = $true
        }
    } catch {
        # Ignore errors while waiting
    }
    
    if (-not $Ready) {
        if ($BridgeProcess.HasExited) {
            Write-Host "❌ AI Engine failed to start. Check ai_agent\bridge.log for errors." -ForegroundColor Red
            exit 1
        }
        Start-Sleep -Seconds 1
        $RetryCount++
    }
}

if (-not $Ready) {
    Write-Host "❌ AI Engine failed to start (Timed out). Check ai_agent\bridge.log for errors." -ForegroundColor Red
    Stop-Process -Id $BridgeProcess.Id -Force
    exit 1
}

Write-Host "✅ AI Inference Engine is READY!" -ForegroundColor Green

# 3. Start Next.js Frontend
Write-Host "🌐 Starting Frontend dashboard..." -ForegroundColor Blue
npm run dev

# Cleanup on exit (this might not run if Ctrl+C kills the whole shell, but it's good practice)
Stop-Process -Id $BridgeProcess.Id -Force