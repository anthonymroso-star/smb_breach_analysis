# INCIDENT FINAL REPORT
Reference: INC-2026-0808B
Classification: Automated Brute-Force / Account Takeover
Target: Ubuntu Storage Server (`192.168.10.10`)

## Executive summary
The laboratory environment experienced an identity-based security incident on 8 August 2026, commencing at 7:44 a.m. BST, during which an unmasked external asset successfully gained unauthorized access to a local network share via an automated credential spray. Sensitive organizational files, including a network topology map and payroll records, were actively accessed during the connection window. The financial impact of the incident is £0, as the attack was safely contained within a controlled sandboxed testing subnet. The incident is now closed and a thorough packet-level forensic investigation has been completed.

## Timeline
* **07:44:33 a.m. BST** — Attacker initiated a connection over TCP port 445. Initial telemetry captured six sequential failed authentication requests targeting a single user profile.
* **07:44:38 a.m. BST** — The automated tools successfully identified valid credentials. The server initialized a privileged session on behalf of the target user, triggering an out-of-hours alert line.
* **07:46:32 a.m. BST** — Attacker established a secondary automated connection to execute rapid directory sweeps. The SIEM dashboard logged the secondary success but remained blind to the preceding failures.
* **07:50:53 a.m. BST** — Attacker severed the communication channel after a total operational window of 6 minutes and 20 seconds. The server completed the final closing of the authentication handles.

## Investigation
The security analyst received the out-of-hours authentication alert on a mobile device and utilized the central SIEM console to investigate the live event.
The root cause of the incident was identified as an internal Server Message Block (SMB2) service exposed with weak account credentials and low-verbosity application logging (`log level = 1`). This configuration allowed the attacker to run an automated tool without triggering standard system authentication failures on the primary SIEM dashboard.
After confirming the logging deficit inside the SIEM data, the team pivoted to a high-fidelity network trace file (`smb_breach.pcapng`). A custom Python script was engineered to unpack the raw application bytes, unmasking the anonymous source IP address as `172.16.0.100` and verifying 150 packets of active data movement.

## Response and remediation
The organization verified a successful authentication breakthrough and subsequent file system data exposure. The server processed the valid credential set with root authority (`uid=0`), the attacker achieved unhindered read access to the target network.
After the analyst executed the custom script across the raw packet bytes, the true scope and impact were confirmed. The threat actor did not remain idle; they successfully opened handles to target and extract three specific text assets: `9xnetwork_map.txt`, `9xpayroll_records.txt`, and `9xpasswords.txt`. The account was immediately flagged for emergency isolation.

## Recommendations
To prevent future recurrences, we are taking the following actions:
* Enforce mandatory Multi-Factor Authentication (MFA) across all local user identity profiles to block automated credential sprays.
* Transition the Samba file configuration to an audited baseline (`log level = 2`) to ensure remote connection IPs print natively to disk.
* Implement strict network segmentation firewalls to restrict SMB port 445 traffic exclusively to verified corporate VPN ranges.

