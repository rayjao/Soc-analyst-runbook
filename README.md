# Soc-analyst-runbook
A practical triage runbook covering 10 of the most common SOC alert types. Built from hands-on experience working across CrowdStrike, Microsoft Sentinel, Entra ID, Check Point Harmony, and Microsoft 365 — not copied from vendor docs.
Each section covers triage steps, IOCs to look for, containment actions, and escalation criteria so you can move fast when an alert fires without second-guessing your next step.
Alert types covered: Phishing, Compromised Account, MFA Fatigue, Endpoint Malware, Ransomware, Privilege Escalation, Impossible Travel, Suspicious Inbox Forwarding, Brute Force/Password Spray, and Suspicious PowerShell Execution.

---

## Table of Contents

1. [Phishing Email Alert](#1-phishing-email-alert)
2. [Compromised Account / Suspicious Sign-In](#2-compromised-account--suspicious-sign-in)
3. [MFA Fatigue Attack](#3-mfa-fatigue-attack)
4. [Endpoint Malware Detection](#4-endpoint-malware-detection)
5. [Ransomware Indicator](#5-ransomware-indicator)
6. [Privilege Escalation Alert](#6-privilege-escalation-alert)
7. [Impossible Travel Alert](#7-impossible-travel-alert)
8. [Suspicious Inbox Forwarding Rule](#8-suspicious-inbox-forwarding-rule)
9. [Brute Force / Password Spray](#9-brute-force--password-spray)
10. [Suspicious PowerShell Execution](#10-suspicious-powershell-execution)

---

## Alert Severity Reference

| Severity | Definition | Response Time |
|----------|------------|---------------|
| Critical | Active threat, confirmed compromise, or data exfil in progress | Immediate |
| High | Strong indicator of compromise, needs urgent investigation | < 15 minutes |
| Medium | Suspicious activity requiring investigation, may be benign | < 1 hour |
| Low | Informational, low confidence, or known noisy alert | < 4 hours |

---

## 1. Phishing Email Alert

**Severity:** High
**Log Sources:** Check Point Harmony / Defender for Office 365 / OfficeActivity
**MITRE ATT&CK:** T1566 — Phishing

### Triage Steps

1. Pull the original email — check sender address, reply-to field, and sending infrastructure (SPF/DKIM/DMARC results)
2. Extract any URLs or attachments and run them through VirusTotal or your sandbox
3. Check if the email was delivered or quarantined — if delivered, find out how many users received it
4. Search mail logs for the same sender domain or subject line across the org
5. Check if any user clicked the link — look at proxy/web filter logs or Defender Safe Links telemetry

### What to Look For

- Mismatched sender display name vs actual email address
- Urgency language ("Your account will be suspended", "Action required")
- Links that redirect through URL shorteners or newly registered domains
- Attachments with macros enabled (.xlsm, .docm)
- Lookalike domains (micros0ft.com, paypa1.com)

### Containment

- If delivered: soft-delete from all mailboxes using Purge in Defender or Exchange Online
- Block sender domain and IP at the email gateway
- If clicked: isolate the endpoint immediately and begin endpoint triage
- Reset credentials for any users who interacted with the email
- Document IOCs (sender, URL, attachment hash) and add to block list

### Escalate If

- Any user clicked a link or opened an attachment
- Credentials were submitted to a phishing page
- The campaign targeted executive accounts

---

## 2. Compromised Account / Suspicious Sign-In

**Severity:** High
**Log Sources:** SigninLogs / AuditLogs / Entra ID Identity Protection
**MITRE ATT&CK:** T1078 — Valid Accounts

### Triage Steps

1. Pull the sign-in logs for the flagged account — look at IP, location, device, and app accessed
2. Check if the sign-in was successful or blocked by Conditional Access
3. Review recent activity — what did they access after signing in? Mail, SharePoint, admin portal?
4. Check for new inbox rules, forwarding rules, or MFA changes made after the sign-in
5. Look for other accounts signing in from the same IP

### What to Look For

- Sign-in from a country the user has never been in
- Sign-in from an anonymous proxy or Tor exit node
- Sign-in outside of normal business hours for that user
- New device or browser not seen before
- Multiple failed attempts followed by a success

### Containment

- Revoke all active sessions immediately (Entra ID → Revoke Sessions)
- Reset the user's password and force MFA re-registration
- Disable the account temporarily if active threat is confirmed
- Review and remove any inbox rules or forwarding rules created during the session
- Check for OAuth apps consented to during the session

### Escalate If

- Admin account was compromised
- Attacker accessed sensitive data or SharePoint libraries
- New accounts or service principals were created during the session

---

## 3. MFA Fatigue Attack

**Severity:** High
**Log Sources:** SigninLogs
**MITRE ATT&CK:** T1621 — Multi-Factor Authentication Request Generation

### Triage Steps

1. Confirm the user is receiving repeated MFA push requests they didn't initiate
2. Pull sign-in logs — verify the attacker has valid credentials (they do, or this wouldn't trigger)
3. Check the source IP — is it a known bad actor IP or anonymized infrastructure?
4. Determine if the user approved any of the MFA requests
5. Check if any successful sign-ins occurred around the same timeframe

### What to Look For

- 10+ MFA push requests in under 30 minutes to the same account
- Requests coming from a foreign or unusual IP
- Any MFA approval that doesn't align with the user's normal login time or location
- User calling the helpdesk confused about MFA requests — this is a strong signal

### Containment

- Contact the user directly — confirm they did not approve anything
- If no approval: reset password, revoke sessions, notify user to deny all pending requests
- If approval occurred: treat as full account compromise and follow Runbook #2
- Consider enforcing number matching MFA to prevent future fatigue attacks

### Escalate If

- User approved a push request
- Attacker successfully authenticated
- Attack is targeting multiple accounts simultaneously (coordinated spray)

---

## 4. Endpoint Malware Detection

**Severity:** High to Critical depending on malware type
**Log Sources:** CrowdStrike Falcon / SecurityEvent / MDE
**MITRE ATT&CK:** T1204 — User Execution / T1059 — Command and Scripting Interpreter

### Triage Steps

1. Pull the detection in CrowdStrike — review process tree, parent process, and execution chain
2. Identify the file hash and run it through VirusTotal
3. Check if the threat was prevented or allowed — was it quarantined or did it execute?
4. Look at what the process tried to do — network connections, file writes, registry changes
5. Check if the same file hash or behavior appeared on other endpoints

### What to Look For

- Malware spawned from Office applications (Word/Excel spawning cmd.exe or PowerShell)
- Encoded PowerShell commands in the process tree
- Outbound connections to unusual IPs or domains after execution
- File drops in temp directories or AppData
- Lateral movement attempts from the infected host

### Containment

- Isolate the endpoint immediately via CrowdStrike Network Containment
- Do not reimage until forensic data is collected (process tree, memory if needed)
- Block the file hash at the platform level
- Check user account tied to the endpoint for signs of credential theft
- Search for the same IOCs across all endpoints in your environment

### Escalate If

- Malware is confirmed ransomware or data stealer
- Lateral movement is detected from the infected host
- The endpoint belongs to an executive or IT admin

---

## 5. Ransomware Indicator

**Severity:** Critical
**Log Sources:** CrowdStrike / OfficeActivity / SecurityEvent
**MITRE ATT&CK:** T1486 — Data Encrypted for Impact / T1485 — Data Destruction

### Triage Steps

1. Confirm the indicator — are files being renamed with unknown extensions? Is a ransom note present?
2. Identify patient zero — which endpoint or user account is the origin?
3. Immediately isolate all affected endpoints via EDR network containment
4. Check for mass file deletion or encryption activity in SharePoint/OneDrive logs
5. Identify how the ransomware got in — phishing, RDP, vulnerable service?

### What to Look For

- High volume of file rename operations in a short window
- Ransom note files dropped in multiple directories
- Shadow copy deletion commands (vssadmin delete shadows)
- Outbound C2 communication before encryption began
- Lateral movement via SMB or RDP to spread to other hosts

### Containment

- **This is an all-hands situation — escalate immediately**
- Isolate affected endpoints from the network
- Disable affected user accounts
- Snapshot any cloud storage before additional files are encrypted
- Notify leadership and initiate your Incident Response Plan
- Do not pay ransom without legal and leadership approval

### Escalate If

- Any confirmed ransomware indicator — this is always an immediate escalation

---

## 6. Privilege Escalation Alert

**Severity:** High
**Log Sources:** AuditLogs / Entra ID
**MITRE ATT&CK:** T1098 — Account Manipulation / T1078.004 — Cloud Accounts

### Triage Steps

1. Identify who assigned the role and to which account
2. Verify if this was a planned change — check change management tickets or Slack/Teams messages
3. Review what the newly privileged account did after the role was assigned
4. Check if the account that made the assignment was itself recently compromised
5. Look for other role assignments made around the same time

### What to Look For

- Global Admin or Privileged Role Admin assigned outside business hours
- Role assigned by a service account or non-admin account (should not be possible, but worth checking)
- New account created and immediately given admin rights
- PIM eligible roles activated without a legitimate business reason

### Containment

- If unauthorized: remove the role assignment immediately
- Revoke sessions for the account that received the elevated role
- Review all actions taken by the account during the elevated period
- Reset credentials for both the assigning account and the target account

### Escalate If

- Global Admin was assigned to an unknown or external account
- Admin account shows signs of compromise
- Multiple privilege escalation events occurred in the same window

---

## 7. Impossible Travel Alert

**Severity:** Medium to High
**Log Sources:** SigninLogs / Entra ID Identity Protection
**MITRE ATT&CK:** T1078 — Valid Accounts

### Triage Steps

1. Pull both sign-in events — confirm locations, timestamps, and whether both were successful
2. Contact the user — did they use a VPN? Are they traveling? Are they aware of both sign-ins?
3. Check what was accessed in each session
4. Look at the device and browser for both sign-ins — are they the same or different?
5. Check for other risky activity tied to either session

### What to Look For

- Two successful sign-ins from geographically impossible locations within an hour
- One sign-in from a known location, one from a high-risk country
- Sign-in from a VPN that routes through an unexpected country
- Different device or browser between the two sessions

### Containment

- If user confirms one sign-in is not theirs: revoke all sessions and reset password immediately
- If VPN explains it: document and close as false positive
- Add a note to the user's account for future reference

### Escalate If

- User cannot explain either sign-in
- Suspicious activity occurred during the foreign session

---

## 8. Suspicious Inbox Forwarding Rule

**Severity:** High
**Log Sources:** OfficeActivity / AuditLogs
**MITRE ATT&CK:** T1114.003 — Email Forwarding Rule

### Triage Steps

1. Pull the rule details — what address is mail being forwarded to? When was it created?
2. Check if the user created it or if it was created during a suspicious session
3. Review sign-in logs around the time the rule was created
4. Determine how long the rule has been active and what mail may have been forwarded
5. Check if other users in the org have similar rules to the same external address

### What to Look For

- Forwarding rule set to an external Gmail, Outlook.com, or unknown domain
- Rule created outside of business hours
- Rule set to forward all mail or mail containing specific keywords (invoice, payment, wire)
- User has no recollection of creating the rule — almost always means compromise

### Containment

- Delete the forwarding rule immediately
- Revoke user sessions and reset password
- Notify the user and review what mail was forwarded during the active window
- Check for BEC indicators — were any financial or vendor emails forwarded?

### Escalate If

- Financial or sensitive data was forwarded externally
- The same external address appears in forwarding rules across multiple mailboxes
- BEC (Business Email Compromise) is suspected

---

## 9. Brute Force / Password Spray

**Severity:** Medium to High
**Log Sources:** SigninLogs
**MITRE ATT&CK:** T1110 — Brute Force

### Triage Steps

1. Determine attack type — is it targeting one account (brute force) or many accounts with one password (spray)?
2. Pull the source IP(s) — is it a single IP or distributed across many?
3. Check if any attempts were successful
4. Identify which accounts were targeted — are any of them admin accounts?
5. Look at timing — is this hitting during off-hours when response is slower?

### What to Look For

- Single account with 15+ failures in a short window = brute force
- Many accounts each with 3-5 failures using the same timestamp = password spray
- Failures followed by a success on any account
- Source IPs resolving to known attack infrastructure or foreign hosting providers

### Containment

- Block the source IP(s) at your perimeter or Conditional Access
- Lock accounts that were successfully breached
- Force password resets on targeted accounts if spray was extensive
- Enable Smart Lockout in Entra ID if not already configured

### Escalate If

- Any account was successfully authenticated during the attack
- Admin or service accounts were targeted

---

## 10. Suspicious PowerShell Execution

**Severity:** High
**Log Sources:** SecurityEvent (EventID 4104) / CrowdStrike
**MITRE ATT&CK:** T1059.001 — PowerShell

### Triage Steps

1. Pull the full script block from EventID 4104 — read what it's actually trying to do
2. Check the parent process — what launched PowerShell? Office app? CMD? A scheduled task?
3. Look at any network connections made during or after execution
4. Check if the script downloaded anything or wrote files to disk
5. Search for the same script block or command on other endpoints

### What to Look For

- Encoded commands (-EncodedCommand or FromBase64String)
- Execution policy bypass flags (-ep bypass, -nop, -windowstyle hidden)
- Download cradles (DownloadString, IEX, Invoke-Expression)
- PowerShell spawned by a non-administrative user
- Execution from a temp directory or unusual path

### Containment

- Isolate the endpoint if the script executed successfully
- Kill the PowerShell process if still running
- Block the script hash or command pattern at the EDR level
- Review what the script accessed or downloaded
- Check user credentials on the affected host for signs of theft

### Escalate If

- Script successfully downloaded and executed a secondary payload
- Lateral movement was detected from the host after execution
- A privileged account was used to execute the script

---

## General Escalation Guidelines

Always escalate when:
- A confirmed compromise involves an admin or executive account
- Data exfiltration is suspected or confirmed
- Ransomware indicators are present anywhere in the environment
- You cannot contain the threat with available tools
- The incident scope is expanding faster than you can respond

---

## Documentation Checklist (Every Incident)

- [ ] Alert source and timestamp
- [ ] Affected user(s) and endpoint(s)
- [ ] Initial triage findings
- [ ] Actions taken and timeline
- [ ] IOCs identified (IPs, hashes, domains, email addresses)
- [ ] Escalation status and who was notified
- [ ] Resolution and lessons learned

---

*Built by Jay Rao | [LinkedIn](https://www.linkedin.com/in/jayrao-/) | Cybersecurity & IT Analyst*
