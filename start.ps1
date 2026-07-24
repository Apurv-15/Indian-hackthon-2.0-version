# Configuration
$PROJECT_ROOT = Get-Location
$PYTHON_EXECUTABLE = Join-Path $PROJECT_ROOT ".venv\Scripts\python.exe"
$BRIDGE_SCRIPT = "$PROJECT_ROOT/ai_agent/bridge.py"
$PORT = 5001

Write-Host "🛡️ Starting AegisAI Integrated System..."

# Pre-startup: Clean up existing processes on ports 3001 and 5001
Write-Host "🧹 Cleaning up previous instances..."
Get-NetTCPConnection -LocalPort 3001, 5001 -ErrorAction SilentlyContinue | ForEach-Object { 
    try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue } catch {} 
}
Start-Sleep -Seconds 1

# 1. Start Python Bridge in the background
Write-Host "🚀 Launching AI Inference Engine..."
$bridgeJob = Start-Job -ScriptBlock {
    param($projectRoot, $python, $script)
    Set-Location $projectRoot
    & "$python" "$script" > ai_agent/bridge.log 2>&1
} -ArgumentList $PROJECT_ROOT, $PYTHON_EXECUTABLE, $BRIDGE_SCRIPT

# Function to kill bridge on exit
$cleanup = {
    Write-Host ""
    Write-Host "🛑 Shutting down..."
    Stop-Job $bridgeJob
    Remove-Job $bridgeJob
}
Register-EngineEvent PowerShell.Exiting -Action $cleanup

# 2. Wait for Bridge to be ready
Write-Host "⏳ Waiting for models to load (this may take a few seconds)..."
$MAX_RETRIES = 180
$RETRY_COUNT = 0
while ($true) {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$PORT/health" -Method GET -TimeoutSec 1 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            break
        }
    } catch {
        # Ignore errors
    }
    Start-Sleep -Seconds 1
    $RETRY_COUNT++
    if ($RETRY_COUNT -ge $MAX_RETRIES) {
        Write-Host "❌ AI Engine failed to start. Check ai_agent/bridge.log for errors."
        Stop-Job $bridgeJob
        Remove-Job $bridgeJob
        exit 1
    }
}

Write-Host "✅ AI Inference Engine is READY!"

# 3. Start Next.js Frontend
Write-Host "🌐 Starting Frontend dashboard..."
Set-Location $PROJECT_ROOT
npm run dev