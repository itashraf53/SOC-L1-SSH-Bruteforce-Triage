# Triage Ticket — SSH Brute Force Alert

*Ticket ID:* SOC-2026-0315-001  
*Analyst:* [Mohammad Ashraf]  
*Date:* 2026-11-18
*Severity:* Critical (one confirmed compromise)  
*Status:* Escalated to Tier 2

---

## Alert Details

*Alert name:* SSH Brute Force — Multiple Failed Passwords  
*Initial rule:* Failed password count > 3 (any user/IP)  
*Data source:* SSH authentication logs (ssh_logs_csv)

---

## Disposition Summary

| src_ip | user | server | failures | successes | Verdict |
|---|---|---|---|---|---|
| 203.0.113.50 | root | db-prod-01 | 7 | 1 | *TRUE POSITIVE — COMPROMISED* |
| 198.51.100.22 | oracle | app-prod-01 | 6 | 0 | *TRUE POSITIVE — ATTEMPTED* |
| 10.0.0.42 | test_user | web-prod-01 | 4 | 1 | *FALSE POSITIVE* |
| 10.0.0.77 | jdoe | web-prod-02 | 2 | 1 | Benign (below threshold) |

---

## Investigation Notes

*Attacker 1 — 203.0.113.50 (COMPROMISED):*
7 failed password attempts in 40 seconds against root on db-prod-01, 
followed by a *successful login* at 11:23:02. Confirmed compromise of 
the database server root account.

*Attacker 2 — 198.51.100.22 (ATTEMPTED):*
6 failed attempts against oracle on app-prod-01 within 2.5 minutes. 
No successful login. Attack attempt only — no credentials believed compromised.

*False Positive — 10.0.0.42 (test_user):*
Internal IP, 4 failures spread over 3 minutes, followed by a success. 
Pattern is consistent with a legitimate user mistyping their password. 
*No malicious activity.*

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Defense Evasion | Valid Accounts | T1078 |

---

## Escalation Reason (L1 → L2)

Confirmed *root compromise* on db-prod-01 from external IP 203.0.113.50. 
This is a *True Positive* requiring immediate containment.

---

## Recommended Actions

1. *Isolate* db-prod-01 from the network (or segment immediately).
2. *Reset* the root password and rotate all credentials on the host.
3. *Hunt* for post-exploitation activity from 203.0.113.50 across all logs.
4. *Block* 203.0.113.50 and 198.51.100.22 at the perimeter firewall.
5. *Audit* SSH access — disable direct root login (PermitRootLogin no).
6. *Enable* fail2ban or equivalent rate-limiting on all internet-facing SSH.

---

## Detection Tuning Applied

*Rule changed from:*
count > 3 failed passwords (no time window, no success check)

*To:*
5+ failed passwords within a 10-minute window *plus* success-correlation 
to auto-label COMPROMISED vs ATTEMPTED.

*Result:* False positive eliminated. Both real attacks retained.
