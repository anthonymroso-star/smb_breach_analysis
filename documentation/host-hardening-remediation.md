# Security Hardening & Post-Incident Remediation Walkthrough

 For incident `INC-2026-0808B`, the security team executed emergency remediation playbooks on the target storage server to invalidate compromised tokens and eliminate systemic application logging deficits.

## Step 1: Emergency Identity Revocation
Because the threat actor utilised valid credentials cracked during the dictionary spray phase, the account password was immediately rotated at the operating system kernel layer:
```bash
sudo passwd dummy_attacker
```

## Step 2: Samba passdb Synchronization
Samba stores credentials independently from standard Linux PAM configurations. The password rotation was synchronised to the local TDB database to block subsequent Port 445 connection requests:
```bash
sudo smbpasswd dummy_attacker
```

## Step 3: Application Log Level Augmentation
To resolve the dashboard blindspot regarding connection socket tracking and authentication failures, the primary configuration file `/etc/samba/smb.conf` was modified under the `[global]` block to increase audit verbosity:
```text
log level = 2
```

## Step 4: Daemon Container Refresh
The file-sharing background services were reloaded to drop active memory connections, commit configuration changes to running state, and initialise the hardened network logging pipeline:
```bash
sudo systemctl restart smbd
```

