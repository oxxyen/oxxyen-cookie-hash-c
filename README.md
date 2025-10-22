# 🍪 OXXYEN Cookie Hash v3.0.0

**Advanced Security Testing Suite for Cookie Harvesting & Password Cracking**  
*Professional-grade, ethically designed for authorized penetration testing and red-team operations.*

> 🔐 **Privacy is a feature. Intelligence is a discipline.**

---

## 🚀 Features

### 🔍 Cookie Intelligence
- Real-time cookie extraction from authenticated sessions
- Secure serialization to structured JSON with integrity hashing (SHA-256)
- HTTP/1.1, HTTP/2, and HTTP/3 support
- TLS fingerprint spoofing (Chrome, Firefox, Safari, Edge, Opera)
- Automatic cookie validation & XSS pattern filtering

### 💥 Password Cracking Engine
- **Dictionary Attack** – Multi-threaded wordlist processing
- **Brute-Force Attack** – Configurable charset & length ranges
- **Pattern-Based Attack** – Common credential heuristics
- **Hybrid & Markov-ready** architecture (extensible)
- Adaptive rate-limiting evasion with per-thread delays

### 🛡️ Operational Security
- Proxy chaining & rotation support (HTTP/SOCKS)
- Stealth mode with real-browser User-Agent emulation
- Secure memory handling (explicit zero-wipe on free)
- Aggressive performance tuning (TCP Fast Open, BBR, compression)

### 🧪 Developer Experience
- Full CLI with intuitive flags & auto-detection
- Real-time progress tracking & success alerts
- Detailed JSON output with metadata & timing
- Thread-safe design with mutex-protected resources

---

## ⚠️ Legal Notice

This tool is intended **exclusively for authorized security assessments**, educational research, and defensive testing **on systems you own or have explicit written permission to test**.

**Unauthorized use is illegal and violates ethical hacking principles.**  
Use responsibly. Respect privacy. Obey the law.

---

## 🛠️ Build Instructions

### Dependencies (Arch Linux / systemd-based)
```bash
sudo pacman -S gcc curl json-c openssl libpthread
```
### Compile
```bash
gcc -O3 -march=native -flto -DNDEBUG -std=gnu17 \
    -lcurl -ljson-c -lssl -lcrypto -lz -lpthread \
    -o cookie_hash cookie_hash.c
```
> ✅ Requires C17/GNU extensions (strdup, strncasecmp, gettimeofday). 


## 🔧 Core Options

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Target authentication endpoint (**required**) |
| `-o`, `--output` | Output file for cookies or results |
| `-U`, `--user` | Username (default: `admin`) |
| `-P`, `--pass` | Password |
| `-x`, `--proxy` | Proxy server (e.g., `http://proxy:8080`) |
| `-a`, `--aggressive` | Enable performance optimizations |
| `-s`, `--stealth` | Use common browser fingerprint |
| `-v`, `--verbose` | Enable detailed logging |

## 🔐 Password Attack Options

| Flag | Description |
|------|-------------|
| `-w`, `--wordlist` | Path to password dictionary |
| `-L`, `--userlist` | Path to username list |
| `-T`, `--threads` | Number of concurrent threads (max: 50) |
| `-m`, `--min-length` | Min password length (brute-force) |
| `-M`, `--max-length` | Max password length |
| `-c`, `--charset` | Custom character set |
| `-D`, `--delay` | Delay between attempts (ms) |

---

## 📂 Output Format

Results are saved as structured JSON with:

- Full cookie metadata (domain, path, expiry, flags)
- Integrity hash (`SHA-256` of `name=value@domain`)
- Attack statistics (attempts, time, success rate)
- Tool version & timestamp

### Example Snippet:
```json
{
  "metadata": {
    "harvest_time": 1729631420,
    "total_cookies": 2,
    "tool": "CookieCommando-Pro",
    "version": "3.0.0",
    "target_url": "https://target.com/login"
  },
  "cookies": [
    {
      "domain": "target.com",
      "name": "sessionid",
      "value": "a1b2c3d4...",
      "secure": true,
      "expires": 1729717820,
      "integrity_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

## 🧠 Philosophy

> **"Where code meets conscience."**

Cookie Commando Pro is built for professionals who demand:

- **Reliability** in high-stakes environments  
- **Auditability** of every memory allocation  
- **Ethical boundaries** in offensive tooling  
- **Zero tolerance** for sloppy or dangerous code

---

## 📜 License

For authorized use only. Not for redistribution or malicious activity.  
© 2025 OXXYEN AI — *Privacy is a feature. Intelligence is a discipline.*

> 🔒 Contact: [@oxxy3n](https://t.me/oxxy3n) (private Telegram)
