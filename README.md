# 🛡️ Red ASM Security Cyber Capstone Project  
## Attack Surface Management: The Blueprint to Cyber Attacks & Defensive Strategies  

> **Attack or Defend. Heads or Tails. ASM reveals the bet that will break the bank.**

---

## 🎥 Final Project Video

🔗  YouTube Link:
https://www.youtube.com/watch?v=OaFekFG9pOg

## 🎯 Project Focus

This project demonstrates a full **Attack Surface Management (ASM)** pipeline integrating both offensive (Red Team) and defensive (Blue Team) strategies.

### Core Objectives
- 🔍 **Attack Surface Management (ASM)**  
  Tools that uncover the target scope for which attackers attack & defenders defend  

- 🚨 **Security Detection & Response**  
  Implementation of:
  - **SIEM** (Wazuh)
  - **SOAR** (Shuffle)
  - **Case Management** (Slack, TheHive)

- ⚔️ **Red vs Blue Team Simulation**  
  Demonstrating attacker pipelines and defender response workflows  

- 🛡️ **System Hardening**
  - ModSecurity WAF
  - Slack Action Buttons for automated response
  - Secure coding (parameterized queries)

- 💉 **SQL Injection Simulation**
  - Exploitation of vulnerable endpoints in OWASP Juice Shop
  - Detection and mitigation via SOC pipeline

- ☁️ **Cyber-Ready Infrastructure**
  - Public-facing vulnerable system
  - Hidden defensive management environment

---

## 🏗️ Architecture Overview

# 🔴 ASM Target (Vulnerable Environment)
- **Dockerized OWASP Juice Shop**
- **Nginx Reverse Proxy**
- **ModSecurity (WAF)**
- **Wazuh Agent** (log + alert forwarding)

#### Hosted Services:
- `shop.redasmsecurity.cloud`  
  → Vulnerable Juice Shop (protected by ModSecurity + Slack response actions)

- `secure-shop.redasmsecurity.cloud`  
  → Hardened Juice Shop (secure backend using parameterized queries)

---

# 🔵 ASM Manager (Defensive Environment)

### 🛡️ SOC Mini Suite (SIEM + SOAR + Case Management)
By: Adam Llado

🔗 Branch Link:
https://github.com/CS4850-ASMCyberProject/RedASMSecurity_Cyber_Capstone_Project/tree/Llado_shuffle_slack

- **Wazuh Manager (SIEM)**  
  → Detects threats from incoming logs  

- **Shuffle (SOAR)**  
  → Automates incident response workflows  

- **TheHive (Case Management)**  
  → Response hub for investigation & case tracking  

- **Python Automation Server**
  - Listens for Shuffle responses  
  - Executes automated actions:
    - Block IPs
    - Disable vulnerable endpoints

---  

### 🔍 ASM Scanning Engine
By: Adam Llado, Kimani Gordon, Alec Sundby

🔗 Branch Link:
https://github.com/CS4850-ASMCyberProject/RedASMSecurity_Cyber_Capstone_Project/tree/Llado_ASM_Scanning_Database_Upgrades

Daily automated scans:

Discovers new assets  
Identifies vulnerabilities  
Feeds data into database and SOC pipeline  

- **MySQL Database**
  - Stores:
    - Discovered assets
    - Vulnerabilities
    - Hardening results

---

# ⚙️ Supporting Infrastructure

- 🌐 **Domain**
  - `redasmsecurity.cloud`

- 💬 **Slack**
  - Main Hub to Investigate Active Cyber Threats
    - `Alerts Channel → Low priority threats`  
    - `Cases Channel → High priority incidents` 

- ☁️ **Cloudflare**
  - DNS + subdomain management  
  - Secure tunnel to access private ASM_Manager services via Internet 

- ⏱️ **Crontab**
  - Automates daily ASM scanning  

- 🐳 **Docker**
  - Containerized deployment of:
    - OWASP Juice Shop
    - Shuffle
    - TheHive  

---

# 🌐 Web Interface (Frontend Dashboard)
By: Austin Abeln

🔗 Website Link:
https://cs4850-asmcyberproject.github.io/RedASMSecurity_Cyber_Capstone_Project/

A web-based dashboard provides visualization and interaction with ASM data, connecting backend systems to a user-friendly interface.

Features: 

Visualizes discovered assets and attack surface  
Displays URL paths and endpoints  
Shows vulnerabilities and scan results  
Interfaces with FastAPI backend and MySQL database  

🔗 Branch Link:
https://github.com/CS4850-ASMCyberProject/RedASMSecurity_Cyber_Capstone_Project/tree/austin-website

## 🧩 Project Structure

```bash
ASM_Manager/
├── ASM_Scanning_Engine/
├── Grafana/
├── MySQL_Database/
├── SOC_Suite/
│   ├── Shuffle/
│   ├── TheHive/
│   └── Wazuh_Manager/

ASM_Target/
├── Dockerized_Juice_Shop_Services/
├── Modsecurity/
├── Nginx_Server/
├── Wazuh_Agent/

Supporting_Services/
├── Cloudflare/
├── Slack/

Website/
```

## 👥 Contributors

- **Adam Llado**  
- **Kimani Gordon**  
- **Austin Abeln**  
- **Alec Sundby**  
