# Splunk SIEM (Security Information and Event Management)

More info: https://blog.aegides.be/splunk_dashboard/

## Lab Setup Overview

For this lab:
- SIEM Platform: **Splunk Enterprise** running on a **Ubuntu Server**
- Client Machine: **Rocky Linux 9** (rocky-web01)  (rsyslog + auditd forwarding)
- Attacker Machine: **Kali Linux** (mainly for SSH brute force)

---

## Auditd Rules Setup

To enable detailed system monitoring, we go to the following file:

```
/etc/audit/rules.d/audit.rules
```

<details>
<summary><strong>📜 Click to expand audit.rules</strong></summary>

```bash
-D
-b 8192
-f 1
--backlog_wait_time 60000

## === EXECUTION ===
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log
-w /bin/bash -p x -k bash_exec
-w /bin/sh -p x -k sh_exec
-w /usr/bin/nc -p x -k netcat_use
-w /usr/bin/ncat -p x -k netcat_use
-w /usr/bin/ssh -p x -k ssh_use

## === PRIV ESCALATION ===
-a always,exit -F arch=b64 -S setuid,setgid -k priv_esc
-a always,exit -F arch=b32 -S setuid,setgid -k priv_esc

## === PERSISTENCE ===
-w /etc/cron.allow -p wa -k cron_mod
-w /etc/cron.d/ -p wa -k cron_mod
-w /etc/cron.daily/ -p wa -k cron_mod
-w /etc/crontab -p wa -k cron_mod
-w /etc/systemd/system/ -p wa -k systemd_backdoor
-w /etc/rc.local -p wa -k rc_persistence

## === LOG TAMPERING ===
-w /var/log/ -p wa -k log_tamper
-w /root/.bash_history -p wa -k history_clear
-w /home/abdullah/.bash_history -p wa -k history_clear

## === EXFILTRATION ===
-w /usr/bin/scp -p x -k exfil
-w /usr/bin/wget -p x -k exfil
-w /usr/bin/curl -p x -k exfil
-w /usr/bin/ftp -p x -k exfil
-w /usr/bin/sftp -p x -k exfil

## === NETWORK ACTIVITY ===
-a always,exit -F arch=b64 -S connect -k netconn
-a always,exit -F arch=b32 -S connect -k netconn
-a always,exit -F arch=b64 -S socket -k socket_create
-a always,exit -F arch=b32 -S socket -k socket_create

## === PROCESS ACTIVITY ===
-a always,exit -F arch=b64 -S fork,vfork,clone -k proc_spawn
-a always,exit -F arch=b32 -S fork,vfork,clone -k proc_spawn

## === SSH BRUTEFORCE LOGGING ===
-w /var/log/secure -p r -k ssh_brute

```
</details>
This ruleset enables logging for:

- **Program execution** (`execve`, `/bin/bash`, `/bin/sh`)
- **Privilege escalation** (`setuid`, `chmod +s`)
- **Persistence techniques** (modifications to `cron.d`, `rc.local`, `systemd`)
- **Sensitive file access** (e.g., `/etc/shadow`, `.bash_history`)
- **Temp file execution** (`/tmp`, `/var/tmp`, `/dev/shm`)
- **Network activity** (e.g., `connect`, `socket`)
- **Exfiltration tools** (`scp`, `curl`, `wget`, `ftp`)

These audit rules allow Splunk to receive enriched log events from `auditd` via `rsyslog`, providing full visibility into attacker behavior without requiring agents or kernel modules.

---

## Dashboard Overview

Below is the custom dashboard I created in Splunk. It covers detections such as SSH brute force, sudo usage, SUID escalation, persistence via cron, suspicious temp files, and data exfiltration.

![Splunk Dashboard](./images/Linux%20Attack%20Detection_2025-04-17%20at%2005.42.11+0200_Splunk.png)



## Mapping to MITRE ATT&CK

This detection lab maps to multiple MITRE ATT&CK techniques, including:

| Technique | Description                         | Covered by                                      |
|-----------|-------------------------------------|-------------------------------------------------|
| T1078     | Valid Accounts                      | Successful SSH login tracking                   |
| T1110.001 | Brute Force: Password Guessing      | SSH brute force detection                       |
| T1059     | Command and Scripting Interpreter   | `execve`, bash/sh audit rules                   |
| T1547.001 | Boot or Logon Autostart via cron    | Cron job modification detection                 |
| T1546.004 | Event Triggered Execution: systemd  | Watching `/etc/systemd/system`                  |
| T1055     | Process Injection (via SUID abuse)  | Detection of SUID privilege escalation attempts |
| T1041     | Exfiltration over C2 channel        | Curl, scp-based exfiltration detection          |

