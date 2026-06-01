#!/bin/bash

echo "Starting Kali Web Enumerator..."

cd /opt/web-enumerator
source venv/bin/activate

# Kill any existing process on port 5000
pkill -f "python3 app.py" 2>/dev/null || true
sleep 1

# Start the application
python3 app.py
