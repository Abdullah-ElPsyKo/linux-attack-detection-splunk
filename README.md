
# Linux Threat Detection Engineering Lab (Splunk SIEM & Auditd)

## Engineering & Lab Overview
This project demonstrates an end-to-end telemetry engineering and threat detection framework designed to capture low-level Linux kernel events and parse them into actionable security intelligence. By leveraging the Linux Audit Subsystem (`auditd`), telemetry is generated natively on endpoints and shipped via network sockets to a centralized SIEM platform for parsing, enrichment, and analysis.

The primary objective is to build high-fidelity detection pipelines covering common post-exploitation tactics—such as lateral movement, privilege escalation, persistence, and data exfiltration—and map them directly to the **MITRE ATT&CK** matrix.

---

## Architecture & Telemetry Pipeline

* **SIEM Core Platform:** Splunk Enterprise deployed on an optimized Ubuntu Server architecture.
* **Target Monitored Endpoint:** Rocky Linux 9 (`rocky-web01`) emitting raw kernel-space event structures.
* **Transport Layer:** Configured `rsyslog` daemon streaming formatted audit records over secure network sockets directly to the Splunk indexing engine.
* **Attacker Infrastructure:** Kali Linux platform simulating targeted adversarial activity (e.g., automated credential stuffing and exploit execution).

---

## Endpoint Telemetry Base Engine (`/etc/audit/rules.d/audit.rules`)

To achieve complete visibility into system state modifications without the overhead of heavy third-party kernel modules, a rigid audit ruleset was implemented to hook critical system calls (such as `execve`, `setuid`, and network socket allocations):

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

## SIEM Dashboard Overview

A custom analytical dashboard was built in Splunk Enterprise to visualize real-time attacks, aggregating indicators for brute-force tracking, unvalidated credential elevation, process spikes, and data egress attempts.

![Splunk Dashboard](/images/Linux%20Attack%20Detection_2025-04-17%20at%2005.42.11%2B0200_Splunk.png)

---

## Tactical Detection Engineering (Splunk SPL)

### 1. Privileged Execution Tracking: Sudo Commands

Monitors administrative behavior by extracting active executing context fields out of structural syslog buffers.

![Sudo Commands](/images/sudo_cmds.png)

```spl
index="linux_logs" sourcetype="syslog" host="rocky-web01" "sudo"
| rex field=_raw "sudo\\[\\d+\\]: (?<executing_user>[^ ]+) : TTY=[^;]+ ; PWD=(?<pwd>[^;]+) ; USER=(?<user>[^;]+) ; COMMAND=(?<command>.+)"
| where isnotnull(command)
| table _time executing_user user pwd command
| sort -_time

```

### 2. Credential Access: SSH Brute Force Identification

Tracks failed remote authentication metrics and groups them by source IP addresses to flag automated brute-force scripts.

![alt text](/images/SSH_failures_single_dig.png)
The image below shows more attempts due to the continues attempts, the screenshot was taken a bit later.
![Failed SSH](/images/SSH_failed_attempts.png)


```spl
index="linux_logs" sourcetype="syslog" "sshd" "Failed password"
| rex "Failed password for (invalid user )?(?<username>\w+) from (?<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by attacker_ip
| sort -count

```

### 3. Remote Access Verification: Successful SSH Session Correlations

Tracks successful authentication events to establish a baseline for authorized remote connections and detect anomalous internal session pivots (Lateral Movement).

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

### 4. Privilege Escalation: SUID Exploitation & Abuse Patterns

Correlates transaction records across split execution events (`EXECVE` / `SYSCALL`) to detect binary manipulation or unvalidated SUID state transformations.

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

### 5. Persistence: Rogue Cron Job Injection

Flags rogue system automation writes or scheduled payload modifications targeting critical system directories.

![cron](/images/cron_persistence.png)

```spl
index="linux_logs" sourcetype="syslog" host="rocky-web01" "COMMAND=" "/etc/cron.d"
| rex "COMMAND=(?<command>.+)"
| rex "sudo\\[\d+\\]: (?<user>\w+)"
| where isnotnull(command) AND isnotnull(user)
| table _time, host, user, command
| sort -_time

```

### 6. Defense Evasion: Binary Execution from Volatile Memory

Intercepts and alerts when system utilities or binary compilation hooks spawn direct execution trees inside transient, world-writable mount boundaries (`/tmp`, `/var/tmp`, `/dev/shm`), a primary hallmark of staged payloads and volatile memory execution.
![temp_exec](/images/sus_temp_files_exec.png)

```spl
index="linux_logs" sourcetype="syslog" ("/tmp/" OR "/dev/shm/" OR "/var/tmp/")
| rex "a1=\"(?<executed>[^\"]+)"
| where like(executed, "/tmp/%") OR like(executed, "/dev/shm/%") OR like(executed, "/var/tmp/%")
| table _time, host, executed
| dedup _time, host, executed
| sort -_time

```

### 7. Exfiltration: Data Egress via Network Tooling

Monitors living-off-the-land network clients (e.g., curl, scp) processing high-severity arguments targeted at critical system configuration files. The capture below catches an active exfiltration of the system credential store (/etc/shadow) via an outbound HTTP POST request.

![exfilt_attempts](/images/exfiltration.png)

```spl
index="linux_logs" sourcetype="syslog" ("curl" OR "scp")
| rex "COMMAND=(?<command>.+)"
| search command="*POST*" OR command="*scp*" OR command="*/etc/shadow*"
| table _time, host, user, command
| sort -_time

```

---

## MITRE ATT&CK Mapping Matrix

| Tactics | Technique ID | Enterprise Vector Description | Detection Metric Layer |
| --- | --- | --- | --- |
| **Initial Access / Credential Access** | **T1110.001** | Brute Force: Password Guessing | Real-time `sshd` log auditing and threshold alerts. |
| **Execution** | **T1059** | Command and Scripting Interpreter | Interception of `execve` boundaries via system rules. |
| **Persistence** | **T1547.001** | Boot or Logon Autostart: Cron | File integrity alerting covering `/etc/cron.d/*` boundaries. |
| **Persistence** | **T1546.004** | Event Triggered Execution: Systemd | Integrity alerting covering `/etc/systemd/system/` writes. |
| **Privilege Escalation** | **T1548.001** | Abuse Elevation Control Mechanism: SUID | Multi-line correlation tracking on active `chmod` system calls. |
| **Exfiltration** | **T1041** | Exfiltration Over C2 Channel | Parameter filtering on standard transfer binaries (`curl`, `scp`). |

---

## Analytical Conclusions & Operational Takeaways

By centralizing OS-level logs and enforcing comprehensive endpoint auditing rules, complete visibility into adversarial behaviors was achieved without the need for invasive host agents.

This environment proves that a resilient detection posture is built through structured log aggregation, concise system metrics parsing, and mapping telemetry streams directly against verified, real-world attack vectors.

```

```
