# Case 1: SOC146 – Phishing Mail Detected – Excel 4.0 Macros

**Platform:** LetsDefend (Monitoring → Investigation channel)
**Alert:** Event ID 93, rule *SOC146 – Phishing Mail Detected – Excel 4.0 Macros*, severity High, type Exchange
**Alert event time:** 2021-06-13 14:13:28 (+03:00)
**Investigated / closed:** 2026-11-22
**Result:** True positive. The platform labels this alert as generated from a real phishing attack.

## 1. Summary

An external sender emailed `lars@letsdefend.io` a short, generic message with a password-protected ZIP attached. The recipient's host (`LarsPRD`) then made outbound proxy requests from `excel.exe` to two unrelated external domains and ran `regsvr32.exe` against two DLLs. Together these indicate the attachment was opened and executed. The host was contained and the sender IP and two URLs were added as artifacts.

## 2. Email analysis

Screenshot: [01-email-details.png](../screenshots/case1-soc146/01-email-details.png)

| Field | Value |
|-------|-------|
| From | `trenton@tritowncomputers[.]com` |
| To | `lars@letsdefend[.]io` |
| Subject | `RE: Meeting Notes` |
| Sender IP | `24.213.228.54` |
| Date | 2021-06-13 16:11:18 |
| Action (at triage) | Unknown (not yet blocked or allowed) |
| Body | "Hello! Please inspect your docs as one document that you can find through the attachment." |
| Attachment | `11f44531fb088d31307d87b01e8eabff` (ZIP, password shown in the message as `infected`) |

Indicators in the email itself:

- **Vague, generic body** with no specific meeting detail, despite the "Meeting Notes" subject.
- **Password-protected archive.** The password is given in the message, a common way to stop mail scanners from inspecting the contents.
- **External sender** writing to an internal user and asking them to open an attachment.
- The `RE:` prefix implies an existing conversation, but the message gives no sign of one.

## 3. Attachment analysis (VirusTotal)

Screenshots: [02](../screenshots/case1-soc146/02-virustotal-attachment.png), [03](../screenshots/case1-soc146/03-virustotal-relations.png)

- ZIP SHA-256: `38b01a12b8dcd39ebdcf9e97772e848237330eb227e1ccee80125564b27377e5`
- Size 106.80 KB, tagged `zip` and `encrypted`.
- **Detections: 0 / 62**, with VirusTotal's own warning: *"This file is password-protected, security vendors may not have been able to look into it."* Community score −3, with 13 community comments.
- The **Relations** view lists related files:

| Name | Type | Detections |
|------|------|-----------|
| `iroto.dll` | Win32 DLL | 25 / 71 |
| `iroto1.dll` | Win32 DLL | 25 / 71 |
| `research-1646684671.xls` | MS Excel spreadsheet | 40 / 61 |
| `11f44531fb088d31307d87b01e8eabff.zip` | ZIP | 10 / 58 |
| three further files listed by hash only | file | not scanned |

- A community comment on the sample gives it a threat score of 10/10 and a `#malware` tag. This is a third-party opinion, so I treated it as supporting context only.

## 4. Did the user act on it? (endpoint and log evidence)

Screenshots: [04](../screenshots/case1-soc146/04-proxy-logs-excel.png), [05](../screenshots/case1-soc146/05-terminal-history-regsvr32.png)

**Host:** `LarsPRD`, `172.16.17.57`, Windows 10 64-bit, domain `letsdefend.local`, primary user Lars.

**Proxy logs** (Log Management, filter *Source Address contains 172.16.17.57*, 2 events):

| Time | Process | Destination | URL (defanged, truncated in the log view) |
|------|---------|-------------|------------------------------------------|
| 2021-06-13 16:20:10 | `excel.exe` | `188.213.19.81:443` | `hxxps://nws[.]visionconsulting[.]ro/N1G1KCXA…` |
| 2021-06-13 16:20:38 | `excel.exe` | `192.232.219.67:443` | `hxxps://royalpalm[.]sparkblue[.]lk/vCNhYrq3…` |

Excel reaching out to unrelated external domains over HTTPS is not normal spreadsheet behaviour and fits a macro downloading a payload.

**Command history** for the same host (Endpoint Security → Terminal History):

| Time | Command |
|------|---------|
| 2021-06-10 09:21 | `whoami` |
| 2021-06-10 09:22 | `ipconfig /all` |
| 2021-06-10 09:23 | `dir` |
| 2021-06-13 16:20 | `regsvr32.exe -s ../iroto.dll` |
| 2021-06-13 16:21 | `regsvr32.exe -s ../iroto1.dll` |

*The Terminal History panel displays the two `regsvr32` commands as 14:20 and 14:21; they are shown here in the same time reference as the proxy logs.*

`regsvr32.exe` silently registering DLLs named exactly like the two DLLs in the VirusTotal relations (`iroto.dll`, `iroto1.dll`) ties the host activity to the attachment.

## 5. Sequence of events

1. **16:11:18**: email from `trenton@tritowncomputers[.]com` sent to Lars with the ZIP attached.
2. **16:20:10 and 16:20:38**: `excel.exe` on `LarsPRD` contacts `nws[.]visionconsulting[.]ro` and `royalpalm[.]sparkblue[.]lk`.
3. **16:20 and 16:21**: `regsvr32.exe` registers `iroto.dll`, then `iroto1.dll`.
4. Analyst response: host contained, artifacts added, alert closed as a true positive.

## 6. Indicators of compromise (defanged)

| Type | Value |
|------|-------|
| Sender address | `trenton@tritowncomputers[.]com` |
| Sender IP | `24.213.228.54` |
| Attachment (ZIP) SHA-256 | `38b01a12b8dcd39ebdcf9e97772e848237330eb227e1ccee80125564b27377e5` |
| Related files | `iroto.dll`, `iroto1.dll`, `research-1646684671.xls` |
| URL / host | `hxxps://nws[.]visionconsulting[.]ro/` (`188.213.19.81`) |
| URL / host | `hxxps://royalpalm[.]sparkblue[.]lk/` (`192.232.219.67`) |

## 7. Verdict

**Malicious: true positive.** The evidence for it:

1. Unsolicited external email with a generic lure and a password-protected attachment.
2. The attachment hides from scanners (0/62 with an explicit encrypted-file warning) while related files score 25–40 detections.
3. `excel.exe` on the recipient's host contacted two unrelated external URLs.
4. `regsvr32.exe` registered `iroto.dll` and `iroto1.dll`, matching the related files.

I recorded that the attachment **was opened** by the user (the playbook step for this alert).

## 8. Response actions

Screenshots: [06 – containment](../screenshots/case1-soc146/06-host-contained.png), [07 – artifacts](../screenshots/case1-soc146/07-artifacts-added.png), [08 – closed alert](../screenshots/case1-soc146/08-closed-alert.png)

- **Contained** `LarsPRD` through the Endpoint Security containment toggle.
- **Added artifacts:** sender IP `24.213.228.54` (sender IP), `nws[.]visionconsulting[.]ro` and `royalpalm[.]sparkblue[.]lk` (commented as C2 or malicious).
- **Closed** the alert as a true positive.

Further steps in a real environment: block the sender domain and both URLs at the proxy, search the mail gateway for other recipients of the same sender or attachment, reset Lars's credentials, and reimage the host after forensic collection.

## 9. Likely ATT&CK mapping (my interpretation)

| Technique | Evidence |
|-----------|----------|
| T1566.001 Phishing: Spearphishing Attachment | ZIP attachment in email |
| T1204.002 User Execution: Malicious File | `excel.exe` activity after delivery |
| T1218.010 System Binary Proxy Execution: Regsvr32 | `regsvr32.exe -s` on both DLLs |

## 10. Lessons learned

- A low or zero detection count on an encrypted archive says very little. I need to check relations, community context and endpoint behaviour before treating a file as safe.
- The email alone told me "suspicious". The proxy and command-line logs on the recipient's host are what showed the attachment had actually run.
- Building a single timeline across email, proxy and endpoint data made the attack sequence much clearer than reading each source on its own.
