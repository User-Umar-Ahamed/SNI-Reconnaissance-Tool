# 🔍 SNI Reconnaissance Tool

## 🧠 Introduction

Server Name Indication (SNI) is a critical extension of the TLS protocol that allows a client to specify which hostname it is attempting to connect to during the TLS handshake. In restrictive network environments — such as those enforcing deep packet inspection, DNS filtering, or national-level censorship — identifying a **valid, unblocked SNI** is essential for establishing legitimate encrypted tunnels through proxies like **V2Ray/Xray (VLESS over TLS)**.

This project presents a purpose-built **SNI Reconnaissance Tool** — a Python desktop application that automates the discovery of valid SNI candidates by performing **dual-stage testing**: a TLS handshake probe followed by a firewall reachability check. The tool was developed as the original software component of a Final Year Project titled *"Implementing a Secure and Censorship-Resistant Proxy Tunnel for Restricted Network Environments"* at Kingston University London.

---

## 🌐 SNI & Proxy Tunnels — Overview

In a VLESS-over-TLS proxy setup, the client disguises its traffic as legitimate HTTPS traffic to a known domain. The **serverName** field in the TLS configuration determines which domain is presented as the SNI during the handshake. If that domain is blocked or flagged, the connection fails — even if the underlying proxy server is functioning correctly.

### Why SNI Selection Matters:
- A blocked domain causes immediate connection failure at the firewall level.
- A domain that fails the TLS handshake will break the tunnel's disguise.
- Only domains that pass **both** TLS and reachability tests are safe to use.

This tool solves this problem by systematically testing domains across multiple sources and returning only those that are confirmed valid.

---

## 🔍 Key Components

| Component | Description |
|---|---|
| **main.py** | Single entry-point launcher; hosts all GUI logic using CustomTkinter |
| **core/scanners.py** | Dual-stage scanning engine — TLS handshake + reachability check |
| **core/database.py** | SQLite persistence layer with CASCADE DELETE for scan history |
| **core/export_manager.py** | Multi-format export engine (CSV, JSON, TXT) |
| **data/common_sites.txt** | Curated domain list for the Common Sites scan mode |
| **requirements.txt** | Dependency manifest (customtkinter, Pillow) |

---

## ⚙️ How It Works — Dual-Stage Testing

The scanner applies a two-step validation process to every domain:

### Stage 1 — DNS Resolution Check
The tool resolves the domain via `socket.gethostbyname()`. If the domain resolves to a blocked IP (e.g., `0.0.0.0`, `127.0.0.1`, or private RFC 1918 ranges), it is immediately marked as **Blocked** without further testing.

### Stage 2 — TLS Handshake Probe
Using Python's `ssl` library, the tool attempts a full TLS handshake on port 443, presenting the domain as the SNI value. A successful handshake confirms the domain is valid for use in TLS-based proxy configurations.

### Stage 3 — Firewall Reachability Verification
A secondary socket connection verifies the domain is not blocked at the network perimeter. Domains that pass TLS but fail reachability are still marked **Blocked**, as they would not function reliably as an SNI in restricted environments.

### Results:
- ✅ **Valid SNI** — TLS handshake succeeded AND domain is reachable — **safe to use**
- 🚫 **Blocked** — Domain is intercepted or unreachable — **do not use**

---

## 🧰 Project Implementation Phases

1. **Designed the tool architecture** around the CustomTkinter GUI framework
2. **Implemented the BaseScanner class** with `ThreadPoolExecutor` for parallel scanning (up to 20 workers)
3. **Developed three scan modes** — DNS Cache, Common Sites, and Custom Domain
4. **Built the SQLite database layer** with relational schema and CASCADE DELETE
5. **Integrated the ExportManager** supporting CSV, JSON, and plain-text output
6. **Packaged everything under main.py** as a single-entry-point desktop application

---

## 🖥️ Scan Modes

### 🔹 1. DNS Cache Scan (Windows)
Extracts domains from the local Windows DNS resolver cache using `ipconfig /displaydns`. These are domains the machine has recently resolved — making them highly relevant to the user's own browsing context and network environment.

### 🔹 2. Common Sites Scan
Tests a curated list of globally recognised domains (search engines, CDNs, social platforms, streaming services) stored in `data/common_sites.txt`. Useful for quick identification of reachable CDN-backed domains that work well as SNI fronts.

### 🔹 3. Custom Domain Scan
Accepts a user-supplied list of domain names for targeted testing. Ideal for operators who have specific candidate domains in mind or wish to test domains identified through OSINT or prior research.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/User-Umar-Ahamed/SNI-Reconnaissance-Tool.git
cd SNI-Reconnaissance-Tool

# Install dependencies
pip install -r requirements.txt

# Launch the tool
python main.py
```

### Requirements

```
customtkinter>=5.2.0
Pillow>=10.0.0
```

> Python 3.10+ recommended. On Windows, DNS Cache Scan requires no additional privileges.

---

## 🚀 Usage

1. Launch the tool via `python main.py`
2. From the **Dashboard**, click **New Scan**
3. Select a scan type: `DNS Cache`, `Common Sites`, or `Custom`
4. Monitor real-time progress as domains are tested in parallel
5. Review results — domains marked ✅ **Valid SNI** are safe to use
6. Export results in CSV, JSON, or TXT format as needed
7. Access previous scans anytime via **History**

---

## 🔧 Using Results in Xray / V2Ray

Once a **Valid SNI** domain is identified, insert it into your Xray/V2Ray client configuration under `streamSettings`:

```json
{
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "valid-domain.com"
    }
  }
}
```

> ⚠️ Only use domains confirmed as ✅ **Valid SNI** by the tool. Using a blocked domain will cause the tunnel to fail immediately.

---

## 💾 Database Schema

Scan history is persisted using **SQLite** with a relational schema and `CASCADE DELETE` to ensure referential integrity when scans are removed.

```sql
CREATE TABLE scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT UNIQUE NOT NULL,
    scan_type TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE results (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL,
    domain   TEXT NOT NULL,
    port     INTEGER NOT NULL,
    latency  REAL,
    status   TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```

---

## 📤 Export Formats

| Format | Contents |
|---|---|
| **CSV** | Domain, Status, Latency (ms), Use as SNI flag |
| **JSON** | Full structured export with metadata, timestamps, and per-domain results |
| **TXT** | Human-readable summary with Valid SNIs sorted by latency and Blocked domains listed separately |

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + N` | New Scan |
| `Ctrl + H` | View History |
| `Ctrl + S` | Save / Export Results |
| `Esc` | Return to Dashboard |

---

## 🧠 Skills Gained

| Category | Skills Developed |
|---|---|
| **Network Programming** | Raw TLS handshake testing, DNS resolution, socket-level reachability probing |
| **GUI Development** | Desktop UI design with CustomTkinter, real-time progress tracking |
| **Concurrent Programming** | Parallel domain scanning via `ThreadPoolExecutor` |
| **Database Engineering** | SQLite schema design with relational integrity and CASCADE DELETE |
| **Security Research** | SNI-based traffic disguise, censorship circumvention techniques |
| **Software Engineering** | Modular architecture, single-entry-point design, cross-platform packaging |

---

## 🏁 Conclusion

The SNI Reconnaissance Tool demonstrates how targeted, automated network probing can solve a real-world problem in censorship-circumvention infrastructure. By combining TLS handshake validation with firewall reachability checking in a parallel, GUI-driven application, the tool provides operators with confident, actionable SNI candidates — removing the guesswork from proxy tunnel configuration in restricted environments.

---

## 👨‍💻 Built By

**Umar Ahamed**  
Cybersecurity Student • Kingston University London  
Final Year Project — CI6600 | BSc Cyber Security & Digital Forensics  
Passionate about **network security, censorship circumvention**, and **secure systems development.**

⭐ Connect via GitHub: [User-Umar-Ahamed](https://github.com/User-Umar-Ahamed)
