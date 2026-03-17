
# Configuration
PROJECT_ROOT=$(pwd)

# Detect Python executable
if [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_EXECUTABLE="$PROJECT_ROOT/.venv/bin/python"
elif [ -f "$PROJECT_ROOT/venv/bin/python" ]; then
    PYTHON_EXECUTABLE="$PROJECT_ROOT/venv/bin/python"
else
    PYTHON_EXECUTABLE="python3"
fi

BRIDGE_SCRIPT="$PROJECT_ROOT/ai_agent/bridge.py"
PORT=5001

echo "🛡️ Starting AegisAI Integrated System..."

# 1. Start Python Bridge in the background
echo "🚀 Launching AI Inference Engine..."
cd "$PROJECT_ROOT/ai_agent"
"$PYTHON_EXECUTABLE" bridge.py > bridge.log 2>&1 &
BRIDGE_PID=$!

# Function to kill bridge on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down..."
    kill $BRIDGE_PID
    exit
}
trap cleanup SIGINT SIGTERM

# 2. Wait for Bridge to be ready
echo "⏳ Waiting for models to load (this may take a few seconds)..."
MAX_RETRIES=60
RETRY_COUNT=0
while ! curl -s http://127.0.0.1:$PORT/health > /dev/null; do
    sleep 1
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "❌ AI Engine failed to start. Check ai_agent/bridge.log for errors."
        kill $BRIDGE_PID
        exit 1
    fi
done

echo "✅ AI Inference Engine is READY!"

# 3. Start Next.js Frontend
echo "🌐 Starting Frontend dashboard..."
cd "$PROJECT_ROOT"
npm run dev
