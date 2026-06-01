# 🔍 Web Enumeration & Attack Testing Tool

A professional‑grade security tool for **web application reconnaissance** and **automated vulnerability testing**.  
It discovers subdomains, ports, static/dynamic pages, technologies, and then executes **70+ attack tests** with **CVSS scoring**, **step‑by‑step exploitation logs**, and **0% false‑positive goal**.

---

## 🚀 Features

### 🌐 Web Enumeration
- Subdomain discovery with resolved IP addresses  
- Open port scanning + filtered/closed port detection  
- Static vs dynamic webpage classification (URL patterns + response analysis)  
- Server header extraction and technology fingerprinting (CMS, frameworks, libraries)  
- Detailed methodology and techniques used during reconnaissance  

### ⚔️ Attack Testing (70+ attacks)
- **Injection** – SQLi (boolean + time‑based), HTML Injection, Host Header Injection  
- **Cross‑Site Scripting** – Reflected, Stored, DOM, Blind  
- **Access Control** – IDOR, Privilege Escalation (horizontal/vertical), Broken Access Control  
- **Server‑Side** – SSRF, LFI, RFI, File Upload, RCE (via upload)  
- **Authentication** – Broken Authentication, Default Credentials, Clear‑text Password, Rate Limiting  
- **Information Disclosure** – Version disclosure, Sensitive File Exposure, Metadata leakage  
- **Client‑Side** – Clickjacking, CORS misconfiguration, Missing Security Headers  
- **Session Management** – CSRF, Missing Logout/Lockout policies, Reset Link expiration  
- **And many more** – Open Redirect, Captcha bypass, Long password DoS, Back button refresh attack  

For every vulnerability, the tool shows:
- **Exact location** (URL / domain / IP / path)  
- **Payload used**  
- **Step‑by‑step exploitation** taken by the tool  
- **CVSS score** and **Severity** (None/Low/Medium/High/Critical)  
- **Probability %** and **Impact description**

### 🔄 Self‑Updating
- Automatically checks for new attack definitions and tool updates over the internet  
- One‑click update from the web interface (no Git required)

### 📊 Web Interface
- Clean two‑tab interface (Enumeration / Attack Testing)  
- Real‑time progress bars and live log window  
- Expandable vulnerability details with exploitation steps  
- Exportable results (copy to clipboard)

---

## 📦 Installation

### 1. Clone or download the tool
```bash
git clone https://github.com/YOUR_USERNAME/web-enumerator.git
cd web-enumerator
```
*(or download the zip and extract)*

### 2. Set up Python virtual environment
```bash
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
# On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
python3 app.py
```

### 5. Open your browser
Navigate to `http://localhost:5000`

---

## 🖥️ Usage

### Web Enumeration Tab
- Enter a target (domain, subdomain, or IP address)  
- Click **Start Enumeration**  
- View results: subdomains, open/filtered ports, static/dynamic pages, server list, technologies, additional recon info

### Attack Testing Tab
- Enter the same target  
- Select any number of attacks from the categorized list (or use **Select All**)  
- Click **Run Selected Attacks**  
- Attacks run **sequentially** (one after another)  
- Expand each vulnerability to see:  
  - Location  
  - Payload used  
  - Detailed exploitation steps  
  - CVSS score and severity  
  - Impact and evidence

### Manual Upgrade (Self‑Update)
- Click the **🔄 Upgrade Tool (Self‑Update)** button in the header  
- The tool will fetch the latest version from GitHub and restart automatically

---

## 🔧 Configuration (Auto‑Update)

To enable self‑update, edit the top of `app.py` and replace the placeholders with your own GitHub repository URLs:
```python
VERSION_URL = "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/version.txt"
UPDATE_ZIP_URL = "https://github.com/YOUR_USERNAME/YOUR_REPO/archive/refs/heads/main.zip"
```
Then create a `version.txt` file in the project root containing your current version number (e.g., `1.0.0`).

---

## ⚠️ Legal & Ethical Notice

**This tool is for authorised security testing and educational purposes only.**  
Using it against systems without explicit permission is illegal. The author assumes no liability for misuse.

---

## 📄 Requirements

- Python 3.8+  
- Flask  
- Flask-Cors  
- requests  
- dnspython  
- beautifulsoup4  
- urllib3  

All are included in `requirements.txt`.

---

## 🤝 Contributing

Pull requests and suggestions are welcome. Please open an issue first to discuss any major changes.

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

Built with ❤️ for the security community. Special thanks to all open‑source projects that made this possible.

---

*Happy (authorised) hacking!* 🔐
