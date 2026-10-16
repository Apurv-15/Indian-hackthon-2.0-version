#!/usr/bin/env bash
set -eo pipefail

# Configuration
PROJECT_ROOT=$(pwd)

# Detect Python executable
if [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_EXECUTABLE="$PROJECT_ROOT/.venv/bin/python"
    GUNICORN_EXECUTABLE="$PROJECT_ROOT/.venv/bin/gunicorn"
elif [ -f "$PROJECT_ROOT/venv/bin/python" ]; then
    PYTHON_EXECUTABLE="$PROJECT_ROOT/venv/bin/python"
    GUNICORN_EXECUTABLE="$PROJECT_ROOT/venv/bin/gunicorn"
else
    PYTHON_EXECUTABLE="python3"
    GUNICORN_EXECUTABLE="gunicorn"
fi

BRIDGE_SCRIPT="$PROJECT_ROOT/ai_agent/bridge.py"
PORT=5001

echo "🛡️ Starting AegisAI Integrated System..."

# Auto-clear previous Python bytecode caches
echo "🧹 Clearing Python caches & logs..."
find "$PROJECT_ROOT" -type d -name "__pycache__" -exec rm -rf "{}" + 2>/dev/null || true
find "$PROJECT_ROOT" -type f -name "*.pyc" -delete 2>/dev/null || true
# Clear any stray process on ports 5001 & 3001
lsof -ti:5001 -ti:3001 | xargs kill -9 2>/dev/null || true
sleep 1

# 1. Start Python Bridge in the background
echo "🚀 Launching AI Inference Engine..."
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export PYTORCH_ENABLE_MPS_FALLBACK=1
export PYTORCH_MPS_HIGH_WATERMARK_RATIO=0.0
export CUDA_VISIBLE_DEVICES=""
export PYTORCH_DISABLE_MPS=1
cd "$PROJECT_ROOT/ai_agent"

if [ -f "$GUNICORN_EXECUTABLE" ]; then
    echo "⚡ Using Gunicorn WSGI server..."
    "$GUNICORN_EXECUTABLE" --workers 1 --threads 4 --bind 127.0.0.1:5001 bridge:app > bridge.log 2>&1 &
else
    echo "⚡ Using Flask server..."
    "$PYTHON_EXECUTABLE" bridge.py > bridge.log 2>&1 &
fi
BRIDGE_PID=$!

# Function to kill bridge on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down AegisAI..."
    if [ -n "${BRIDGE_PID:-}" ]; then
        kill "$BRIDGE_PID" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 2. Wait for Bridge to be ready
echo "⏳ Waiting for models to load..."
MAX_RETRIES=60
RETRY_COUNT=0
while ! curl -s http://127.0.0.1:$PORT/health > /dev/null; do
    sleep 1
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "❌ AI Engine failed to start. Check ai_agent/bridge.log for errors."
        cat bridge.log
        kill "$BRIDGE_PID" 2>/dev/null || true
        exit 1
    fi
done

echo "✅ AI Inference Engine is READY on port $PORT!"

# 3. Start Next.js Frontend
echo "🌐 Starting Frontend dashboard..."
cd "$PROJECT_ROOT"
npm run dev
