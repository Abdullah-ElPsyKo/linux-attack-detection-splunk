# Linux Threat Detection Engineering Lab (Splunk SIEM & Auditd)

## Overview

This project demonstrates a Linux detection engineering lab built around **auditd**, **rsyslog**, and **Splunk Enterprise**.

A Rocky Linux endpoint generates audit events, forwards them to a centralized Splunk server, and analyzes them using custom SPL queries. The lab focuses on detecting common attack techniques such as privilege escalation, persistence, brute-force attacks, command execution, and data exfiltration, with detections mapped to the **MITRE ATT&CK** framework.

---

## Architecture

| Component | Purpose |
|-----------|---------|
| **Splunk Enterprise** | Collects, indexes, and visualizes endpoint telemetry |
| **Rocky Linux 9 (`rocky-web01`)** | Generates audit events using `auditd` |
| **rsyslog** | Forwards audit logs to Splunk |
| **Kali Linux** | Simulates attacker activity for testing detections |

---

## Audit Rules (`/etc/audit/rules.d/audit.rules`)

The detection pipeline is built on Linux Audit (`auditd`). Custom audit rules monitor critical system activity including:

- Process execution (`execve`)
- Privilege escalation (`setuid`, `setgid`)
- Persistence mechanisms (Cron, Systemd)
- Network activity
- Process creation
- Log tampering
- Common data exfiltration tools (`curl`, `scp`, `wget`, `ftp`)
- SSH authentication activity

```bash
-D
-b 8192
-f 1
--backlog_wait_time 60000

## === EXECUTION (MITRE T1059) ===
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log
-w /bin/bash -p x -k bash_exec
-w /bin/sh -p x -k sh_exec
-w /usr/bin/nc -p x -k netcat_use
-w /usr/bin/ncat -p x -k netcat_use
-w /usr/bin/ssh -p x -k ssh_use

## === PRIVILEGE ESCALATION (MITRE T1548 / T1068) ===
-a always,exit -F arch=b64 -S setuid,setgid -k priv_esc
-a always,exit -F arch=b32 -S setuid,setgid -k priv_esc

## === PERSISTENCE VECTORS (MITRE T1547.001 / T1546.004) ===
-w /etc/cron.allow -p wa -k cron_mod
-w /etc/cron.d/ -p wa -k cron_mod
-w /etc/cron.daily/ -p wa -k cron_mod
-w /etc/crontab -p wa -k cron_mod
-w /etc/systemd/system/ -p wa -k systemd_backdoor
-w /etc/rc.local -p wa -k rc_persistence

## === DEFENSE EVASION / LOG TAMPERING (MITRE T1562.001) ===
-w /var/log/ -p wa -k log_tamper
-w /root/.bash_history -p wa -k history_clear
-w /home/abdullah/.bash_history -p wa -k history_clear

## === EXFILTRATION CHANNELS (MITRE T1041) ===
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

## === CREDENTIAL ACCESS / SSH BRUTEFORCE ===
-w /var/log/secure -p r -k ssh_brute

```

---

## Splunk Dashboard

A custom Splunk dashboard provides a real-time overview of endpoint activity, including authentication attempts, process execution, privilege escalation events, and potential data exfiltration.

![Splunk Dashboard](/images/Linux%20Attack%20Detection_2025-04-17%20at%2005.42.11%2B0200_Splunk.png)

---

# Detection Rules

Each detection includes the SPL query, supporting dashboard, and the attack technique it is designed to identify.

---

## 1. Privileged Command Execution (sudo)

Extracts executed commands from sudo logs to monitor administrative activity.

![Sudo Commands](/images/sudo_cmds.png)

```spl
index="linux_logs" sourcetype="syslog" host="rocky-web01" "sudo"
| rex field=_raw "sudo\\[\\d+\\]: (?<executing_user>[^ ]+) : TTY=[^;]+ ; PWD=(?<pwd>[^;]+) ; USER=(?<user>[^;]+) ; COMMAND=(?<command>.+)"
| where isnotnull(command)
| table _time executing_user user pwd command
| sort -_time

```

---

## 2. SSH Brute Force Detection

Counts failed SSH authentication attempts by source IP to identify brute-force attacks.

![SSH Attempts](/images/SSH_failures_single_dig.png)

The image below was captured later during the attack, showing the increased number of failed login attempts.

![Failed SSH](/images/SSH_failed_attempts.png)

```spl
index="linux_logs" sourcetype="syslog" "sshd" "Failed password"
| rex "Failed password for (invalid user )?(?<username>\w+) from (?<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by attacker_ip
| sort -count

```

---

## 3. Successful SSH Sessions

Displays successful SSH logins to establish a baseline of legitimate remote access and help identify unusual authentication patterns.

![Successful Logins](/images/successful_SSH_logins.png)

```spl
index="linux_logs" sourcetype="syslog" "sshd" ("USER_START" OR "USER_AUTH")
| rex "acct=\"(?<user>[^\"]+)"
| rex "addr=(?<ip>\d+\.\d+\.\d+\.\d+)"
| rex "exe=\"(?<exe>[^\"]+)"
| search res=success exe="/usr/sbin/sshd"
| dedup _time, user, ip
| table _time, host, user, ip
| sort -_time

```

---

## 4. SUID Privilege Escalation

Correlates multi-line audit events to detect SUID modifications and privilege escalation attempts.

![SUID](/images/suid_priv_esc.png)

```spl
index="linux_logs" sourcetype="syslog" ("type=EXECVE" OR "type=SYSCALL") ( "chmod" OR "u+s" )
| rex field=_raw "msg=audit\\((?<audit_id>[^)]+)\\):"
| eventstats values(_raw) as all_logs by audit_id
| eval joined = mvjoin(all_logs, " ")
| rex field=joined "(?<uid_field>(A|E|F|S)?UID)=\"?(?<user>[^\\s\"]+)\"?"
| rex field=joined "a2=\\\"(?<target_file>[^\"]+)"
| stats latest(_time) as _time values(user) as user values(target_file) as target_file values(host) as host by audit_id
| table _time host user target_file

```

---

## 5. Cron Persistence

Detects modifications to cron jobs that could be used for persistence.

![Cron Persistence](/images/cron_persistence.png)

```spl
index="linux_logs" sourcetype="syslog" host="rocky-web01" "COMMAND=" "/etc/cron.d"
| rex "COMMAND=(?<command>.+)"
| rex "sudo\\[\d+\\]: (?<user>\w+)"
| where isnotnull(command) AND isnotnull(user)
| table _time, host, user, command
| sort -_time

```

---

## 6. Execution from Temporary Directories

Detects binaries executed from `/tmp`, `/var/tmp`, and `/dev/shm`, locations commonly abused for staging payloads or fileless execution.

![Temporary Execution](/images/sus_temp_files_exec.png)

```spl
index="linux_logs" sourcetype="syslog" ("/tmp/" OR "/dev/shm/" OR "/var/tmp/")
| rex "a1=\"(?<executed>[^\"]+)"
| where like(executed, "/tmp/%") OR like(executed, "/dev/shm/%") OR like(executed, "/var/tmp/%")
| table _time, host, executed
| dedup _time, host, executed
| sort -_time

```

---

## 7. Data Exfiltration

Monitors common transfer utilities such as `curl` and `scp` for activity that may indicate data exfiltration.

The example below captures an attempt to transfer `/etc/shadow`.

![Data Exfiltration](/images/exfiltration.png)

```spl
index="linux_logs" sourcetype="syslog" ("curl" OR "scp")
| rex "COMMAND=(?<command>.+)"
| search command="*POST*" OR command="*scp*" OR command="*/etc/shadow*"
| table _time, host, user, command
| sort -_time

```

---

# MITRE ATT&CK Mapping

| Tactic | Technique | Detection |
|---------|-----------|-----------|
| Credential Access | T1110.001 | SSH brute-force detection |
| Execution | T1059 | Process execution (`execve`) |
| Persistence | T1547.001 | Cron monitoring |
| Persistence | T1546.004 | Systemd monitoring |
| Privilege Escalation | T1548.001 | SUID monitoring |
| Exfiltration | T1041 | Network transfer utilities |

---

# What I Learned

Building this lab improved my understanding of:

- Linux Audit (`auditd`)
- Endpoint telemetry collection
- Log forwarding with `rsyslog`
- Splunk Enterprise administration
- SPL query development
- Detection engineering
- MITRE ATT&CK mapping
- Linux persistence techniques
- Privilege escalation detection
- Security monitoring pipelines
