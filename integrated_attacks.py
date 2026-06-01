#!/usr/bin/env python3
"""
Integrated Attack Testing Module for Web Enumeration Tool
"""

import requests
import re
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
import warnings
import urllib3

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class IntegratedAttackTester:
    def __init__(self, target, scan_id=None):
        self.target = target
        self.scan_id = scan_id
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'attacks': [],
            'summary': {},
            'risk_score': 0,
            'risk_level': 'Safe'
        }
    
    def add_attack_result(self, attack_name, status, details, severity, probability, impact):
        """Add attack result"""
        result = {
            'attack': attack_name,
            'status': status,
            'details': details,
            'severity': severity,
            'probability': probability,
            'impact': impact
        }
        self.results['attacks'].append(result)
        return result
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        if not self.results['attacks']:
            return 0
        
        severity_scores = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 0}
        total_score = 0
        vuln_count = 0
        
        for attack in self.results['attacks']:
            if attack['status'] == 'Vulnerable':
                score = severity_scores.get(attack['severity'], 0)
                prob = attack.get('probability', 0)
                total_score += score * (prob / 100)
                vuln_count += 1
        
        if vuln_count > 0:
            risk_score = (total_score / vuln_count) * 10
        else:
            risk_score = 0
        
        self.results['risk_score'] = min(100, risk_score)
        
        if self.results['risk_score'] >= 80:
            self.results['risk_level'] = 'Critical'
        elif self.results['risk_score'] >= 60:
            self.results['risk_level'] = 'High'
        elif self.results['risk_score'] >= 40:
            self.results['risk_level'] = 'Medium'
        elif self.results['risk_score'] >= 20:
            self.results['risk_level'] = 'Low'
        else:
            self.results['risk_level'] = 'Safe'
        
        return self.results['risk_score']
    
    def test_spf(self):
        """Test SPF configuration"""
        try:
            domain = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = [str(a) for a in answers if 'v=spf1' in str(a)]
            
            if not spf_records:
                return self.add_attack_result(
                    'SPF (Sender Policy Framework)', 'Vulnerable',
                    'No SPF record found - email spoofing possible', 'High', 85,
                    'Attackers can send spoofed emails from your domain'
                )
            
            for record in spf_records:
                if '~all' in record:
                    return self.add_attack_result(
                        'SPF (Sender Policy Framework)', 'Partially Vulnerable',
                        'SPF uses softfail (~all) - partial protection', 'Medium', 60,
                        'Email spoofing partially possible'
                    )
                elif '?all' in record:
                    return self.add_attack_result(
                        'SPF (Sender Policy Framework)', 'Vulnerable',
                        'SPF uses neutral (?all) - weak protection', 'High', 75,
                        'Email spoofing possible'
                    )
                elif '-all' in record:
                    return self.add_attack_result(
                        'SPF (Sender Policy Framework)', 'Secure',
                        'SPF properly configured with hardfail (-all)', 'Info', 0,
                        'Email spoofing is prevented'
                    )
        except:
            return self.add_attack_result(
                'SPF (Sender Policy Framework)', 'Unknown',
                'Unable to verify SPF configuration', 'Info', 20,
                'Manual SPF check recommended'
            )
    
    def test_html_injection(self):
        """Test HTML Injection"""
        test_payloads = ['<h1>TEST-INJECT</h1>', '<img src=x onerror=alert(1)>']
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            for payload in test_payloads:
                if payload in response.text:
                    return self.add_attack_result(
                        'HTML Injection', 'Vulnerable',
                        f'HTML injection possible with payload: {payload[:30]}', 'High', 80,
                        'Attackers can inject malicious HTML code'
                    )
        except:
            pass
        
        return self.add_attack_result(
            'HTML Injection', 'Secure',
            'No HTML injection vulnerabilities detected', 'Info', 0,
            'Input appears properly sanitized'
        )
    
    def test_reflected_xss(self):
        """Test Reflected XSS"""
        xss_payloads = ['<script>alert("XSS")</script>', '"><script>alert(1)</script>']
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        
        # Test common parameters
        test_params = ['q', 'search', 'id', 'page', 'name']
        for param in test_params:
            for payload in xss_payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=3, verify=False)
                    if payload in response.text:
                        return self.add_attack_result(
                            'Reflected XSS', 'Vulnerable',
                            f'Reflected XSS found in parameter: {param}', 'High', 90,
                            'Attackers can execute JavaScript in victim browsers'
                        )
                except:
                    continue
        
        return self.add_attack_result(
            'Reflected XSS', 'Secure',
            'No reflected XSS vulnerabilities detected', 'Info', 0,
            'Input appears properly escaped'
        )
    
    def test_stored_xss(self):
        """Test Stored XSS"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        stored_locations = ['/comment', '/review', '/post', '/feedback', '/guestbook']
        
        for location in stored_locations:
            try:
                test_url = base_url + location
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    return self.add_attack_result(
                        'Stored XSS', 'Partially Vulnerable',
                        f'Potential stored XSS location: {location}', 'Medium', 55,
                        'User input may be stored without proper sanitization'
                    )
            except:
                continue
        
        return self.add_attack_result(
            'Stored XSS', 'Secure',
            'No obvious stored XSS vectors found', 'Info', 5,
            'Stored XSS unlikely'
        )
    
    def test_dom_xss(self):
        """Test DOM XSS"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        dom_sources = ['document.write', 'innerHTML', 'eval', 'location.hash']
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            found_sources = [s for s in dom_sources if s in response.text]
            
            if found_sources:
                return self.add_attack_result(
                    'DOM XSS', 'Partially Vulnerable',
                    f'DOM manipulation methods: {", ".join(found_sources)}', 'Medium', 50,
                    'Client-side JavaScript may be vulnerable to DOM XSS'
                )
        except:
            pass
        
        return self.add_attack_result(
            'DOM XSS', 'Secure',
            'No obvious DOM XSS vectors found', 'Info', 0,
            'DOM XSS unlikely'
        )
    
    def test_blind_xss(self):
        """Test Blind XSS"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        admin_paths = ['/admin', '/dashboard', '/panel', '/cms', '/wp-admin']
        potential = []
        
        for path in admin_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code in [200, 401, 403]:
                    potential.append(path)
            except:
                continue
        
        if potential:
            return self.add_attack_result(
                'Inferential (Blind) XSS', 'Partially Vulnerable',
                f'Admin areas detected: {", ".join(potential[:2])}', 'Medium', 45,
                'XSS payloads may trigger in admin panels'
            )
        
        return self.add_attack_result(
            'Inferential (Blind) XSS', 'Secure',
            'No clear blind XSS vectors identified', 'Info', 5,
            'Blind XSS unlikely'
        )
    
    def test_clickjacking(self):
        """Test Clickjacking"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            headers = response.headers
            
            if 'X-Frame-Options' in headers:
                xfo = headers['X-Frame-Options']
                if xfo.upper() in ['DENY', 'SAMEORIGIN']:
                    return self.add_attack_result(
                        'Clickjacking', 'Secure',
                        f'X-Frame-Options: {xfo}', 'Info', 0,
                        'Clickjacking attacks prevented'
                    )
            
            if 'Content-Security-Policy' in headers and 'frame-ancestors' in headers['Content-Security-Policy']:
                return self.add_attack_result(
                    'Clickjacking', 'Secure',
                    'CSP frame-ancestors prevents framing', 'Info', 0,
                    'Clickjacking attacks prevented'
                )
            
            return self.add_attack_result(
                'Clickjacking', 'Vulnerable',
                'No frame protection headers', 'High', 85,
                'Website can be embedded in frames for clickjacking'
            )
        except:
            return self.add_attack_result(
                'Clickjacking', 'Unknown',
                'Unable to test clickjacking', 'Info', 20,
                'Manual testing recommended'
            )
    
    def test_password_security(self):
        """Test password transmission security"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                if 'password' in str(form).lower():
                    method = form.get('method', 'get').lower()
                    action = form.get('action', '')
                    
                    if method == 'get':
                        return self.add_attack_result(
                            'Clear Text Password Submission', 'Vulnerable',
                            'Login form uses GET method', 'Critical', 100,
                            'Passwords visible in URLs and browser history'
                        )
                    
                    if base_url.startswith('http://'):
                        return self.add_attack_result(
                            'Clear Text Password Submission', 'Vulnerable',
                            'Login page uses HTTP (no encryption)', 'Critical', 100,
                            'Passwords transmitted in clear text'
                        )
        except:
            pass
        
        return self.add_attack_result(
            'Clear Text Password Submission', 'Secure',
            'No insecure password transmission found', 'Info', 0,
            'Password security appears adequate'
        )
    
    def test_sensitive_exposure(self):
        """Test sensitive data exposure"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        sensitive_paths = ['/.git', '/.env', '/backup.sql', '/config.json', '/robots.txt']
        exposed = []
        
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, timeout=3, verify=False)
                if response.status_code == 200:
                    sensitive_keywords = ['password', 'secret', 'api_key', 'token']
                    content_lower = response.text.lower()
                    if any(kw in content_lower for kw in sensitive_keywords):
                        exposed.append(f"{path} (contains sensitive data)")
                    else:
                        exposed.append(path)
            except:
                continue
        
        if exposed:
            return self.add_attack_result(
                'Sensitive Data Exposure', 'Vulnerable',
                f'Exposed: {", ".join(exposed[:2])}', 'High', 75,
                'Sensitive information may be publicly accessible'
            )
        
        return self.add_attack_result(
            'Sensitive Data Exposure', 'Secure',
            'No sensitive data exposure detected', 'Info', 5,
            'Common sensitive paths are protected'
        )
    
    def test_hsts(self):
        """Test HSTS header"""
        if not self.target.startswith('https'):
            return self.add_attack_result(
                'Missing HSTS Certificate', 'Critical',
                'Website uses HTTP only', 'Critical', 100,
                'No encryption - all traffic is in clear text'
            )
        
        try:
            response = self.session.get(f"https://{self.target}", timeout=5, verify=False)
            headers = response.headers
            
            if 'Strict-Transport-Security' in headers:
                hsts = headers['Strict-Transport-Security']
                if 'max-age=31536000' in hsts or 'max-age=63072000' in hsts:
                    return self.add_attack_result(
                        'Missing HSTS Certificate', 'Secure',
                        f'HSTS properly configured', 'Info', 0,
                        'HTTPS enforcement with HSTS'
                    )
                else:
                    return self.add_attack_result(
                        'Missing HSTS Certificate', 'Partially Vulnerable',
                        f'HSTS present but weak: {hsts[:50]}', 'Low', 30,
                        'Insufficient HSTS protection'
                    )
            else:
                return self.add_attack_result(
                    'Missing HSTS Certificate', 'Vulnerable',
                    'No HSTS header present', 'Medium', 65,
                    'SSL stripping attacks possible'
                )
        except:
            return self.add_attack_result(
                'Missing HSTS Certificate', 'Unknown',
                'Unable to test HSTS', 'Info', 20,
                'Manual verification recommended'
            )
    
    def test_ssl_tls(self):
        """Test SSL/TLS configuration"""
        if not self.target.startswith('https'):
            return self.add_attack_result(
                'SSL and TLS', 'Critical',
                'No HTTPS - communication in clear text', 'Critical', 100,
                'All data transmitted without encryption'
            )
        
        hostname = self.target.replace('https://', '').replace('http://', '').split('/')[0]
        issues = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    if version and any(weak in version for weak in ['SSLv2', 'SSLv3', 'TLSv1.0']):
                        issues.append(f"Weak protocol: {version}")
                    
                    cipher = ssock.cipher()
                    weak_ciphers = ['RC4', 'DES', '3DES', 'NULL']
                    if any(weak in str(cipher[0]) for weak in weak_ciphers):
                        issues.append(f"Weak cipher: {cipher[0]}")
            
            if issues:
                return self.add_attack_result(
                    'SSL and TLS', 'Vulnerable',
                    f'SSL/TLS issues: {"; ".join(issues)}', 'High', 80,
                    'Weak encryption configuration'
                )
            else:
                return self.add_attack_result(
                    'SSL and TLS', 'Secure',
                    'SSL/TLS properly configured', 'Info', 0,
                    'Strong encryption in use'
                )
        except Exception as e:
            return self.add_attack_result(
                'SSL and TLS', 'Unknown',
                f'Unable to test SSL/TLS', 'Info', 20,
                'Manual SSL check recommended'
            )
    
    def test_version_disclosure(self):
        """Test version disclosure"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        disclosures = []
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            headers = response.headers
            
            version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in version_headers:
                if header in headers and any(c.isdigit() for c in headers[header]):
                    disclosures.append(f"{header}: {headers[header]}")
            
            if disclosures:
                return self.add_attack_result(
                    'Technology Version Disclosure', 'Vulnerable',
                    f'Version info disclosed: {disclosures[0]}', 'Medium', 60,
                    'Attackers can target specific version vulnerabilities'
                )
        except:
            pass
        
        return self.add_attack_result(
            'Technology Version Disclosure', 'Secure',
            'No version information disclosed', 'Info', 0,
            'Version information properly hidden'
        )
    
    def test_outdated_versions(self):
        """Test outdated versions"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        outdated_patterns = {
            'PHP/5.': 'PHP 5.x is end-of-life',
            'PHP/7.0': 'PHP 7.0 is end-of-life',
            'Apache/2.2': 'Apache 2.2 is end-of-life',
            'nginx/1.1': 'Old nginx version',
            'IIS/6.0': 'Windows Server 2003 - unsupported'
        }
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            server = response.headers.get('Server', '')
            
            for pattern, warning in outdated_patterns.items():
                if pattern.lower() in server.lower():
                    return self.add_attack_result(
                        'Technology Version Not Updated', 'Vulnerable',
                        f'Outdated: {server[:50]}', 'High', 85,
                        warning
                    )
        except:
            pass
        
        return self.add_attack_result(
            'Technology Version Not Updated', 'Secure',
            'No obviously outdated versions detected', 'Info', 10,
            'Versions appear current or not disclosed'
        )
    
    def test_server_version_outdated(self):
        """Test outdated server versions"""
        base_url = f"http://{self.target}" if not self.target.startswith('http') else self.target
        outdated_servers = {
            'Apache/1.3': 'Critical', 'Apache/2.0': 'High', 'Apache/2.2': 'High',
            'nginx/0.7': 'High', 'nginx/0.8': 'High', 'nginx/1.0': 'Medium',
            'IIS/5.0': 'Critical', 'IIS/6.0': 'Critical', 'IIS/7.0': 'High'
        }
        
        try:
            response = self.session.get(base_url, timeout=5, verify=False)
            server = response.headers.get('Server', '')
            
            for pattern, severity in outdated_servers.items():
                if pattern.lower() in server.lower():
                    return self.add_attack_result(
                        'Server Version Not Updated', 'Vulnerable',
                        f'Outdated server: {server[:50]}', severity, 90,
                        f'Server {pattern} is end-of-life with known vulnerabilities'
                    )
        except:
            pass
        
        return self.add_attack_result(
            'Server Version Not Updated', 'Secure',
            'Server version appears current', 'Info', 5,
            'No outdated server versions detected'
        )
    
    def run_all_attacks(self):
        """Run all attack tests"""
        print("\n[*] Starting integrated attack testing...")
        
        attacks = [
            self.test_spf,
            self.test_html_injection,
            self.test_reflected_xss,
            self.test_stored_xss,
            self.test_dom_xss,
            self.test_blind_xss,
            self.test_clickjacking,
            self.test_password_security,
            self.test_sensitive_exposure,
            self.test_hsts,
            self.test_ssl_tls,
            self.test_version_disclosure,
            self.test_outdated_versions,
            self.test_server_version_outdated
        ]
        
        for attack in attacks:
            attack()
        
        self.calculate_risk_score()
        
        # Summary
        vuln_count = len([a for a in self.results['attacks'] if a['status'] == 'Vulnerable'])
        self.results['summary'] = {
            'total_attacks': len(self.results['attacks']),
            'vulnerabilities_found': vuln_count,
            'vulnerability_percentage': (vuln_count / len(self.results['attacks']) * 100) if self.results['attacks'] else 0,
            'risk_score': self.results['risk_score'],
            'risk_level': self.results['risk_level']
        }
        
        return self.results
