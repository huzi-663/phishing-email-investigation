# Phishing Email Investigation

Three phishing investigations I completed in the LetsDefend training platform as part of my SOC / GRC learning path. Each one answers the same question: **does the evidence support a phishing classification, and why?**

> All material comes from the authorized LetsDefend training environment. Indicators are defanged (`hxxp`, `[.]`). Lab answer keys are deliberately not reproduced.

## Cases at a glance

| # | Case | What arrived | Verdict | Report |
|---|------|--------------|---------|--------|
| 1 | Alert **SOC146 – Phishing Mail Detected – Excel 4.0 Macros** (Event ID 93) | "RE: Meeting Notes" with a password-protected ZIP | **Malicious (true positive)**, host contained | [report/investigation.md](report/investigation.md) |
| 2 | Phishing Analysis challenge: "Website contact form submission" | Bounce notice wrapping spam from an abused web form | **Spam / scam link-bait** | [report/case-2-contact-form-spam.md](report/case-2-contact-form-spam.md) |
| 3 | Phishing Analysis 2 challenge: "Your Account has been locked" | Fake Amazon notice with a "Review Account" button | **Credential phishing** | [report/case-3-amazon-credential-phish.md](report/case-3-amazon-credential-phish.md) |

## Method

For every email I asked the same questions, in this order:

1. **Who sent it?** Display name, address, domain, `Return-Path` / `Reply-To`.
2. **Where did it really come from?** `Received` chain, sending IP, IP/domain WHOIS.
3. **Did authentication pass, and for whose domain?** SPF, DKIM, DMARC.
4. **What does the content push the reader to do?** Urgency, links, attachments.
5. **Where do the links and files actually lead?** Decode or unwrap links, check hashes and reputation.
6. **Did anyone act on it?** Endpoint and proxy logs, process and command history.
7. **Verdict and response.** Classify, contain, record indicators.

## Tools used

- LetsDefend: Monitoring (alert), Log Management, Endpoint Security (host info, terminal history, containment), case artifacts
- VirusTotal (file hash reputation and relations)
- DomainTools WHOIS (IP and domain lookups)
- CyberChef (Base64 decoding of an HTML email body)
- Email client and text editor for reading `.eml` headers

## Key takeaways

- **A clean scan is not a clean file.** The password-protected ZIP in Case 1 showed 0/62 detections on VirusTotal, with a warning that vendors may not have been able to look inside it. Related files in the same VirusTotal relations view had 25–40 detections.
- **Authentication passing is not the same as legitimate.** In Case 3, SPF, DKIM and DMARC all passed, but for the attacker's own domain (`zyevantoby[.]cn`), not Amazon's.
- **Free hosting hides the owner.** In Case 2, WHOIS on the linked blogspot domain only describes Google, not the person behind the page.
- **Logs close the loop.** Case 1 was only confirmed as an *executed* attack by matching the email to proxy and command-line activity on the recipient's host.

## Repository layout

```
phishing-email-investigation/
├── README.md
├── report/
│   ├── investigation.md                    # Case 1 (main investigation)
│   ├── case-2-contact-form-spam.md
│   └── case-3-amazon-credential-phish.md
└── screenshots/
    ├── case1-soc146/
    ├── case2-contact-form-spam/
    └── case3-amazon-credential-phish/
```

## Limitations

- These are guided training labs, not production incidents.
- I did not have sandbox detonation reports or landing-page captures in every case; each report lists what is not verified.

## Disclaimer

This project uses an authorized training environment and simulated investigation material.
