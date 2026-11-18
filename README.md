# SOC-L1-SSH-Bruteforce-Triage
SOC L1 home-lab - SSH brute force alert triage, false positive analysis, and detection tuning in Splunk.
# SOC L1 Home Lab — SSH Brute Force Alert Triage & Detection Tuning

A beginner-friendly SOC analyst portfolio project that simulates the real 
Tier-1 workflow: **alert fires → triage → identify false positive → confirm 
true positive → tune the rule → escalate.**

Built with *Splunk Enterprise* using a synthetic SSH authentication dataset.

---

## 🎯 Objective

To demonstrate the core SOC L1 skill of *alert triage* — deciding whether an 
alert represents a real compromise, an attempted attack, or harmless noise — 
and then improving the detection rule to reduce future false positives without 
losing real threats.

---

## 🧪 Lab Setup

| Item | Detail |
|---|---|
| SIEM | Splunk Enterprise (free edition) |
| Dataset | 24 synthetic SSH authentication events (data/ssh_logs.csv) |
| Index | soc_lab |
| Sourcetype | ssh_logs_csv |
| Scenario date | 2024-03-15 |
| Environment | Linux-style SSH servers (port 22) |

---

## 📖 Scenario

A brute-force detection rule fires:

> "More than 3 failed SSH passwords from one IP/user."

The dataset contains five actors:

| Actor | Description |
|---|---|
| admin (10.0.0.5) | Normal administrator baseline |
| test_user (10.0.0.42) | Employee who mistyped password 4 times → *false positive* |
| jdoe (10.0.0.77) | Below threshold — should never alert |
| root (203.0.113.50) | External attacker who *succeeded* → *compromised* |
| oracle (198.51.100.22) | External attacker who *failed* → *attempted only* |

---

## 🔍 Step-by-Step Investigation

### 1️⃣ Data Ingestion

Uploaded and verified 24 SSH authentication events in Splunk under a custom 
ssh_logs_csv sourcetype with the timestamp format %Y-%m-%dT%H:%M:%SZ.

Open folder SOC_Screenshot to see Data Ingestion Screenshot.


---

### 2️⃣ Naive Alert Fires (with False Positive)

*First rule:* Failed password count > 3 (no time window, no success check).

*Result:* Fired on *3 actors* — including an *internal employee* 
(test_user) whose only crime was typing their password wrong four times. 
That is a *false positive* and a classic source of alert fatigue.

Open folder SOC_Screenshot to see Naive Alert Screenshot.

---

### 3️⃣ True Positive Correlation

Stopped trusting the alert and pivoted to the *full history* of each 
suspicious IP.

*Attacker 203.0.113.50:*
- 7 failed password attempts in 40 seconds
- *1 successful root login on db-prod-01*

*Key rule:* failed attempts alone = attempted attack.  
*Failures followed by a success = confirmed compromise.*

Open folder SOC_Screenshot to see True Positive Correlatio.

---

### 4️⃣ Automated Triage Matrix

Built a single SPL query that classifies *every* IP automatically:

| Verdict | Logic |
|---|---|
| *COMPROMISED* | 5+ failures *AND* ≥1 success |
| *ATTEMPTED* | 5+ failures, no success |
| *BENIGN* | Below threshold |

Open folder SOC_Screenshot to see Automated Triage Matrix Screenshot.

---

### 5️⃣ Detection Tuning (False Positive Reduction)

Tuned the rule from count > 3 (no window) to:

- *5 failures within a 10-minute window*
- *Success-correlation* to auto-label COMPROMISED vs ATTEMPTED

*Result:* false positive eliminated, both real attackers retained.

Open folder SOC_Screenshot to see Detection Tuning Screenshot.

---

### 6️⃣ Alert & Dashboard

Saved the tuned rule as an *hourly scheduled alert* and built a two-panel 
triage dashboard for shift handover.

Open folder SOC_Screenshot to seeAlert & DashboardScreenshot.

---

## 📊 Final Dispositions & Severity

| src_ip | user | server | failures | successes | Verdict | Severity | Action |
|---|---|---|---|---|---|---|---|
| 203.0.113.50 | root | db-prod-01 | 7 | 1 | *COMPROMISED* | *CRITICAL* | Escalate to Tier 2 |
| 198.51.100.22 | oracle | app-prod-01 | 6 | 0 | *ATTEMPTED* | *HIGH* | Block IP |
| 10.0.0.42 | test_user | web-prod-01 | 4 | 1 | *FALSE POSITIVE* | *INFORMATIONAL* | No action |
| 10.0.0.77 | jdoe | web-prod-02 | 2 | 1 | BENIGN | — | No action |

### Why COMPROMISED = Critical

- Confirmed successful login (not just an attempt)
- Compromised account is root (highest privilege on Linux)
- Target is a *production database server* (db-prod-01)
- Source is an *external attacker IP*
- Compromise is *active* — attacker may still be logged in

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | *T1110.001* |
| Defense Evasion / Persistence | Valid Accounts | *T1078* |

---

## 🛠️ Skills Demonstrated

- ✅ Log ingestion & sourcetype configuration in Splunk
- ✅ SPL query writing (stats, eval, bin, case, where, table)
- ✅ Detection rule creation & scheduled alerts
- ✅ *False positive identification & root cause analysis*
- ✅ True positive confirmation via success-correlation
- ✅ Detection tuning (threshold + time-window + correlation logic)
- ✅ Severity assignment based on privilege, asset, and access
- ✅ Dashboard building for shift handover
- ✅ Incident triage documentation & escalation to Tier 2
- ✅ MITRE ATT&CK mapping

---

## 📂 Repository Contents


data/         → synthetic SSH authentication dataset (24 events)
detections/   → tuned SPL detection rule (with tuning notes)
reports/      → formal triage ticket (L1 → L2 escalation)
screenshots/  → evidence screenshots of every investigation phase


---

## 🔁 How to Reproduce

1. Install Splunk Enterprise (free edition).
2. Create an index named soc_lab.
3. Upload data/ssh_logs.csv with:
   - Sourcetype: ssh_logs_csv (new)
   - Timestamp format: %Y-%m-%dT%H:%M:%SZ
4. Run the detection query in detections/ssh_bruteforce_tuned.spl.
5. Review reports/Triage_Ticket_SSH.md for the full triage write-up.

---

## 📌 Scope & Assumptions

- This lab simulates a *Linux SSH environment* (port 22).  
- All IPs, hostnames, and users are *synthetic* (RFC 5737 documentation ranges: 203.0.113.0/24, 198.51.100.0/24).
- The same triage logic applies to *Windows RDP brute force* (port 3389, Event ID 4625/4624) — only the log format differs.

---

## 🎤 One-Sentence Summary

> Took a noisy SSH brute-force alert, proved one hit was a false positive, 
> confirmed a real root compromise on a production database via 
> success-correlation, tuned the rule to remove the noise, and escalated 
> with a written triage ticket and MITRE ATT&CK mapping.

---

Personal SOC L1 portfolio All data is synthetic and for educational use.
