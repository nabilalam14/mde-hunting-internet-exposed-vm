# MDE Hunt: Internet-Exposed Windows VM & RDP Brute Force Attempts

This project documents a Microsoft Defender for Endpoint (MDE) hunting investigation into a Windows VM (`windows-target-1`) that was unintentionally exposed to the public internet and targeted by external brute-force login attempts.

---

## Scenario Overview

During routine maintenance, the security team investigated whether any VMs in a shared services cluster (DNS, Domain Services, DHCP, etc.) were exposed to the internet and whether any brute-force activity succeeded.

**Primary Question:**  
> Did any external attackers successfully authenticate or compromise a valid account while the VM was internet-facing?

---

## Environment

- Platform: Microsoft Defender for Endpoint (Advanced Hunting)
- OS: Windows
- VM: `windows-target-1`
- Exposure: Public internet (RDP)

---

## Timeline & Findings

### 1. Internet Exposure Confirmation

The device was confirmed to be internet-facing for several weeks.

```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc

Last internet-facing timestamp:
2026-01-05T22:55:11.9532147Z
2. Failed Logon Attempts from External IPs

Multiple external IP addresses generated repeated failed logon attempts.

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc

Finding:
Activity consistent with automated password guessing / brute-force attempts.
3. No Successful Logons from Top Offending IPs

The IPs with the highest failure counts were checked for any successful logons.

let RemoteIPsInQuestion = dynamic([
  "185.11.61.192",
  "77.90.185.62",
  "77.90.185.64",
  "185.11.61.198",
  "194.180.48.29"
]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)

Result:
No successful authentications from known brute-force IPs.
4. Successful Logons (Last 30 Days)

Only three accounts logged in successfully.

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| distinct AccountName

Accounts:

    umfd-0

    umfd-1

    dwm-1

5. Validate No Brute Force Against Valid Accounts

Check if these accounts experienced failed logons.

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType in ("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where AccountName in ("umfd-0", "umfd-1", "dwm-1")

Result:
No failed logons for these accounts.
6. Validate labuser Was Not Targeted

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize FailedCount = count()

Result:
Zero failed logons — no brute-force attempt against labuser.
7. Validate Successful Login IP Locations

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType in ("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where AccountName in ("umfd-0", "umfd-1", "dwm-1")
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
| order by LoginCount desc

Finding:
All successful logons originated from expected / normal IP locations.
MITRE ATT&CK Mapping
Observed / Relevant TTPs

TA0006 – Credential Access

    T1110 – Brute Force

        T1110.001 – Password Guessing

            Repeated failed logons from external IPs

TA0001 – Initial Access / TA0005 – Defense Evasion

    T1078 – Valid Accounts

        Legitimate accounts logged in successfully

        No indicators of misuse or compromise

TA0001 – Initial Access (Contextual)

    T1190 – Exploit Public-Facing Application

        System exposure noted (no exploit observed)

Response Actions

    Hardened NSG to allow RDP only from approved endpoints

    Removed public internet exposure

    Implemented account lockout policy

    Implemented Multi-Factor Authentication (MFA)

Final Assessment

    ✅ External brute-force activity detected

    ✅ No successful brute-force authentication

    ✅ No unauthorized access

    ✅ Security posture improved post-incident

Skills Demonstrated

    Microsoft Defender for Endpoint (Advanced Hunting)

    KQL threat hunting

    RDP brute-force analysis

    MITRE ATT&CK mapping

    Incident documentation & response
