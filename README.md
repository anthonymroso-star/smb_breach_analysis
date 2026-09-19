# Enterprise Forensics, SIEM Auditing & Incident Response  
A hands-on engineering lab focused on resolving a hijacked management account, unmasking a hidden intruder by analyzing raw data traffic, finding blind spots in system tracking, and launching immediate security containment steps.
> **Compliance & Data Sanitization Note:** Where applicable, files, scripts, logs, IP addresses, hostnames, and architecture identities within this repository have been sanitized and anonymized in alignment with relevant security frameworks and responsible-disclosure guidelines.
## Lab Architecture Overview  
* **Host Endpoint:** Ubuntu Storage Server `192.168.10.10` (Simulating a localized corporate file-sharing asset).  
* **SIEM Central Control:** Wazuh Indexer & Manager v4.7.5 deployed via Docker Compose.  
* **Forensic Packet Capture:** Wireshark Packet Capture  (`smb_breach_sanitized.pcapng`) capturing local Port 445 network traces.
* **Attacker Asset:** Kali Linux `172.16.0.100` (Utilizing automated password sprays and NetExec protocol testing).  
  
## Key Skills Demonstrated  

| Core Capability | Technical Implementation & Approach |
| :--- | :--- |
| **SIEM Telemetry Triage** | Audited high-severity Level 9 out-of-hours authentication alarms (Rule 17101) within Wazuh. |
| **Behavioral Threat Hunting** | Identified automated machine logic patterns by isolating zero-latency millisecond session timing collisions. |
| **JSON Metadata Analysis** | Dissected raw SIEM database logs to confirm root-level execution privilege mappings (`uid: 0`) and rule iterations. |
| **Defensive Gap Assessment** | Diagnosed default syslog visibility blackouts caused by baseline application configuration levels (`log level = 1`). |
| **Network Forensics** | Programmed an offline byte-parser with Python using Scapy to reconstruct two-way TCP Port 445 conversation timelines. |
| **Binary Dissection** | Leveraged the Python Struct engine to extract raw NT Status error codes (`STATUS_LOGON_FAILURE`) at fixed byte offsets. |
| **Radius Isolation** | Checked application-layer payloads past the 64-byte SMB2 header to decode literal file system transaction strings. |
| **Identity Containment** | Revoked compromised identity handles at both the core OS layer and individual Samba database vaults. |
| **Technical Communication** | Produced application metrics into courtroom-ready incident reports and NIST-compliant briefs. |

  
## 📁 Repository Contents  
* `/documentation`: Holds official incident reports mapped to global security compliance models.  
* `/scripts`: Holds the automated Python forensic wire network trace script and telemetry extraction tools.
* `/artifacts`: Forensic JSON logs captured during live exploit execution.
* `/images` : Holds high-contrast terninal console screenshots and forensic execution visuals  
  
## Featured Project Walkthroughs  
1. **[Incident Response: (NIST SP 800-61 r2) Detection & Forensic Triaging](./documentation/INC-2026-0808B_NIST.md)**  
2. **[Application Layer Forensics: Python / .pcapng File Analysis](./scripts/analyse_smb.py)**
3. **[Network Trace Program Report: Python Generation Output](./images/terminal_report_output.png)**  
4. **[Incident Final Report: INC-2026-0808B Automated Account Takeover](./documentation/final-report_INC-2026-0808B.md)**  
  
## Active Milestones  
  
* [Active Host Containment, Password Revocation, and Service Audit Hardening Walkthrough](./documentation/host-hardening-remediation.md)

