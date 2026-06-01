#!/usr/bin/env python3
import json
import os
import requests

# Replace this URL with your own remote JSON file (GitHub raw, your server, etc.)
REMOTE_ATTACK_URL = "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/attacks/attack_definitions.json"
LOCAL_ATTACK_FILE = "attacks/attack_definitions.json"

def ensure_dirs():
    os.makedirs("attacks", exist_ok=True)

def update_attacks():
    ensure_dirs()
    try:
        resp = requests.get(REMOTE_ATTACK_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            with open(LOCAL_ATTACK_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"[+] Attacks updated to version {data.get('version', 'unknown')}")
            return data
    except Exception as e:
        print(f"[-] Failed to fetch remote attacks: {e}")
    if os.path.exists(LOCAL_ATTACK_FILE):
        with open(LOCAL_ATTACK_FILE, 'r') as f:
            return json.load(f)
    return None

def get_attack_list():
    data = update_attacks()
    if data and 'attacks' in data:
        return data['attacks']
    return []
