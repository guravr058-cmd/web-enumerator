#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import socket
import dns.resolver
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import warnings
import urllib3
import zipfile
import io
import shutil
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from attack_updater import get_attack_list, update_attacks
from accurate_attacks import AccurateAttackTester

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'kali-secret-key-2024'
CORS(app)

active_scans = {}
active_attacks = {}

# ------------------- SIMPLE SELF-UPDATE -------------------
VERSION_URL = "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/version.txt"
UPDATE_ZIP_URL = "https://github.com/YOUR_USERNAME/YOUR_REPO/archive/refs/heads/main.zip"

def get_current_version():
    """Read local version from version.txt file."""
    try:
        with open("version.txt", "r") as f:
            return f.read().strip()
    except:
        return "1.0.0"

def check_for_updates():
    """Check remote version and download if newer."""
    try:
        resp = requests.get(VERSION_URL, timeout=10)
        if resp.status_code == 200:
            remote_version = resp.text.strip()
            local_version = get_current_version()
            if remote_version != local_version:
                print(f"[!] New version {remote_version} available (current: {local_version}). Updating...")
                # Download zip
                zip_resp = requests.get(UPDATE_ZIP_URL, timeout=30)
                if zip_resp.status_code == 200:
                    with zipfile.ZipFile(io.BytesIO(zip_resp.content)) as z:
                        # Extract to a temporary directory
                        extract_path = "/tmp/web_enumerator_update"
                        if os.path.exists(extract_path):
                            shutil.rmtree(extract_path)
                        z.extractall(extract_path)
                        # Find the inner folder (repo-name-main)
                        for item in os.listdir(extract_path):
                            if item.endswith("-main"):
                                source = os.path.join(extract_path, item)
                                # Copy all files except venv, .git, etc.
                                for root, dirs, files in os.walk(source):
                                    for file in files:
                                        if file.endswith(".py") or file.endswith(".html") or file.endswith(".json") or file == "requirements.txt":
                                            rel_path = os.path.relpath(os.path.join(root, file), source)
                                            dest = os.path.join("/opt/web-enumerator", rel_path)
                                            os.makedirs(os.path.dirname(dest), exist_ok=True)
                                            shutil.copy2(os.path.join(root, file), dest)
                                break
                        # Update version file
                        with open("/opt/web-enumerator/version.txt", "w") as f:
                            f.write(remote_version)
                        print("[+] Update complete. Restarting...")
                        # Restart the application
                        python = sys.executable
                        os.execl(python, python, *sys.argv)
            else:
                print("[+] Tool is up to date.")
        else:
            print("[-] Could not check for updates.")
    except Exception as e:
        print(f"[-] Update check failed: {e}")

# ------------------- ENUMERATION ENGINE -------------------
class WebScanner:
    def __init__(self, target, scan_id):
        self.target = target
        self.scan_id = scan_id
        self.base_url = f"http://{target}" if not target.startswith('http') else target
        self.base_url = self.base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.results = {
            'target': target,
            'status': 'running',
            'subdomains': [],
            'open_ports': [],
            'filtered_ports': [],
            'static_pages': [],
            'dynamic_pages': [],
            'server_list': [],
            'technologies': [],
            'additional_info': {}
        }

    def run(self):
        try:
            domain = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            # 1. Subdomain enumeration
            common_subs = ['www', 'mail', 'api', 'blog', 'admin', 'dev', 'test', 'stage', 'ftp', 'smtp']
            for sub in common_subs:
                subdomain = f"{sub}.{domain}"
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    for a in answers:
                        self.results['subdomains'].append({'subdomain': subdomain, 'ip': str(a)})
                except:
                    pass

            # 2. Port scanning
            common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,8888,27017]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((domain, port))
                    if result == 0:
                        services = {
                            21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
                            111:'RPC',135:'RPC',139:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',
                            993:'IMAPS',995:'POP3S',1433:'MSSQL',3306:'MySQL',3389:'RDP',
                            5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',
                            8888:'HTTP-Alt',27017:'MongoDB'
                        }
                        self.results['open_ports'].append({'port': port, 'service': services.get(port, 'Unknown')})
                    else:
                        self.results['filtered_ports'].append({'port': port, 'state': 'filtered'})
                    sock.close()
                except:
                    self.results['filtered_ports'].append({'port': port, 'state': 'filtered'})

            # 3. Web endpoint discovery (static/dynamic classification)
            paths = ['', '/', '/admin', '/login', '/api', '/test', '/robots.txt', '/sitemap.xml', '/index.html', '/index.php', '/about', '/contact']
            static_pages = []
            dynamic_pages = []
            servers = set()
            for protocol in ['http', 'https']:
                base = f"{protocol}://{domain}"
                for path in paths:
                    url = base + path
                    try:
                        resp = self.session.get(url, timeout=3, verify=False)
                        if resp.status_code == 200:
                            # Determine static vs dynamic
                            is_dynamic = (any(x in url for x in ['?', '=', '.php', '.asp', '.jsp', '.do']) or
                                          ('text/html' in resp.headers.get('Content-Type', '') and 
                                           ('?' in url or '=' in url)))
                            page_type = 'dynamic' if is_dynamic else 'static'
                            page_info = {
                                'url': url,
                                'status': resp.status_code,
                                'size': len(resp.content),
                                'title': self.extract_title(resp.text),
                                'type': page_type
                            }
                            if page_type == 'static':
                                static_pages.append(page_info)
                            else:
                                dynamic_pages.append(page_info)
                            if 'server' in resp.headers:
                                servers.add(resp.headers['server'])
                    except:
                        pass
            self.results['static_pages'] = static_pages
            self.results['dynamic_pages'] = dynamic_pages
            self.results['server_list'] = list(servers)

            # 4. Technology detection
            technologies = []
            try:
                resp = self.session.get(f"http://{domain}", timeout=3, verify=False)
                if 'server' in resp.headers:
                    technologies.append({'name': resp.headers['server'], 'category': 'Server'})
                if 'X-Powered-By' in resp.headers:
                    technologies.append({'name': resp.headers['X-Powered-By'], 'category': 'Framework'})
                # CMS detection
                if 'wp-content' in resp.text.lower() or 'wp-includes' in resp.text.lower():
                    technologies.append({'name': 'WordPress', 'category': 'CMS'})
                if 'django' in resp.text.lower():
                    technologies.append({'name': 'Django', 'category': 'Framework'})
                if 'laravel' in resp.text.lower():
                    technologies.append({'name': 'Laravel', 'category': 'Framework'})
            except:
                pass
            self.results['technologies'] = technologies

            # 5. Additional info
            self.results['additional_info'] = {
                'ip_address': socket.gethostbyname(domain),
                'domain': domain,
                'url_base': self.base_url,
                'total_endpoints': len(static_pages) + len(dynamic_pages),
                'methodology': 'Passive & Active recon: subdomain brute force, TCP port scan, HTTP probing, static/dynamic classification via URL patterns & response analysis.',
                'techniques': 'DNS enumeration, TCP connect scanning, HTTP GET requests, HTML parsing, header analysis.'
            }
            self.results['status'] = 'completed'
        except Exception as e:
            self.results['status'] = 'error'
            self.results['error'] = str(e)
        return self.results

    def extract_title(self, html):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.text.strip() if title else 'No title'
        except:
            return 'Could not parse'

# ------------------- ATTACK RUNNER -------------------
def run_attacks_sequential(target, attack_ids, storage_id):
    tester = AccurateAttackTester(target)
    results = tester.run_selected_attacks(attack_ids)
    total = len(results)
    vuln_count = len([r for r in results if r['status'] == 'Vulnerable'])
    risk_score = (vuln_count / total * 100) if total > 0 else 0
    summary = {
        'total_attacks': total,
        'vulnerabilities_found': vuln_count,
        'vulnerability_percentage': (vuln_count / total * 100) if total > 0 else 0,
        'risk_score': risk_score,
        'risk_level': 'Critical' if risk_score >= 80 else 'High' if risk_score >= 60 else 'Medium' if risk_score >= 40 else 'Low' if risk_score >= 20 else 'Safe'
    }
    active_attacks[storage_id] = {'attacks': results, 'summary': summary}

# ------------------- API ROUTES -------------------
@app.route('/')
def index():
    return render_template('integrated_interface.html')

@app.route('/api/attack_list')
def attack_list():
    return jsonify(get_attack_list())

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    target = request.json.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target required'}), 400
    scan_id = int(datetime.now().timestamp())
    def scan():
        scanner = WebScanner(target, scan_id)
        active_scans[scan_id] = scanner.run()
    threading.Thread(target=scan).start()
    return jsonify({'scan_id': scan_id, 'message': 'Enumeration started'})

@app.route('/api/scan_results/<int:scan_id>')
def scan_results(scan_id):
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    return jsonify({'status': 'running'}), 202

@app.route('/api/run_attacks', methods=['POST'])
def run_attacks():
    data = request.json
    target = data.get('target', '').strip()
    attack_ids = data.get('attack_ids', [])
    if not target or not attack_ids:
        return jsonify({'error': 'Target and attack IDs required'}), 400
    storage_id = int(datetime.now().timestamp())
    threading.Thread(target=run_attacks_sequential, args=(target, attack_ids, storage_id)).start()
    return jsonify({'attack_session_id': storage_id, 'message': 'Attack sequence started'})

@app.route('/api/attack_results/<int:session_id>')
def attack_results(session_id):
    if session_id in active_attacks:
        return jsonify(active_attacks[session_id])
    return jsonify({'status': 'running'}), 202

@app.route('/api/upgrade', methods=['POST'])
def upgrade():
    """Manual trigger for self-update."""
    threading.Thread(target=check_for_updates).start()
    return jsonify({'message': 'Update check started. If a new version is found, the tool will restart.'})

if __name__ == '__main__':
    print("="*60)
    print("🔐 Integrated Web Enumeration & Attack Testing Tool (Auto‑update enabled)")
    print("🌐 http://localhost:5000")
    print("="*60)
    # Check for updates on startup (non-blocking)
    threading.Thread(target=check_for_updates, daemon=True).start()
    threading.Thread(target=update_attacks, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
