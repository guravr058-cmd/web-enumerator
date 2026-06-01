cat > /opt/web-enumerator/start.sh << 'EOF'
#!/bin/bash
cd /opt/web-enumerator
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
EOF
chmod +x /opt/web-enumerator/start.sh
