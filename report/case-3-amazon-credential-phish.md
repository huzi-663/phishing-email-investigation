# Case 3: "Your Account has been locked" (fake Amazon notice)

**Platform:** LetsDefend (Phishing Analysis 2 challenge)
**Classification reached:** Credential phishing (brand impersonation)

## 1. What was received

Screenshot: [01-email-display.png](../screenshots/case3-amazon-credential-phish/01-email-display.png)

| Field | Value |
|-------|-------|
| Display name | `Amazn` (misspelled) |
| From address | `amazon@zyevantoby[.]cn` |
| To | `saintington73@outlook.com` |
| Subject | `Your Account has been locked` |
| Shown in client | Tue 7/13/2021 4:40 PM |

First red flags, before any header work:

- The address domain is `zyevantoby[.]cn`, which has nothing to do with Amazon.
- The display name is a misspelling of the brand.
- A "your account is locked" subject creates urgency.

## 2. Header analysis

Screenshots: [02-authentication-results.png](../screenshots/case3-amazon-credential-phish/02-authentication-results.png), [03-from-date-messageid.png](../screenshots/case3-amazon-credential-phish/03-from-date-messageid.png)

| Header | Value |
|--------|-------|
| `Return-Path` | `amazon@zyevantoby.cn` |
| `Authentication-Results` | `spf=pass` (sender IP `45.156.23.138`, `smtp.mailfrom=zyevantoby.cn`); `dkim=pass` (`header.d=zyevantoby.cn`); `dmarc=pass action=none header.from=zyevantoby.cn` |
| `Received-SPF` | Pass: `zyevantoby.cn` designates `45.156.23.138` as a permitted sender; `helo=mta0.zyevantoby.cn` |
| `DKIM-Signature` | `d=zyevantoby.cn`, `i=amazon@zyevantoby.cn` |
| `Date` | `Wed, 14 Jul 2021 01:40:32 +0900` |
| `Message-ID` | `<000756bf516d$9bad2034$6e61f7fb$@vinuqou>` |

**Authentication passed, but that does not make the email legitimate.** SPF, DKIM and DMARC all passed for the attacker's own domain, `zyevantoby[.]cn`. This only proves the mail really came from that domain, not that the domain is Amazon. Nothing in the headers connects the message to `amazon.com`.

Timing note: the `Date` header converts to 2021-07-13 16:40:32 UTC. The first Microsoft hop records receipt at 19:14:57 UTC, which is 2 h 34 m 25 s later. The `Date` header is set by the sender, so I recorded the gap but did not draw a conclusion from it.

## 3. Hidden link (Base64 body)

Screenshot: [04-cyberchef-decoded-link.png](../screenshots/case3-amazon-credential-phish/04-cyberchef-decoded-link.png)

The HTML body in the raw message is Base64 encoded. Decoding it in CyberChef (*From Base64*) shows a button titled **"Review Account"** whose link was wrapped by Outlook SafeLinks. The wrapper's `originalSrc` shows the real destination:

```
hxxps://amaozn[.]zzyuchengzhika[.]cn/?mailtoken=saintington73@outlook[.]com
```

- **`amaozn`** is a typo-squat of `amazon` (the letters `z` and `o` are swapped).
- The domain is registered under `.cn`, unrelated to Amazon.
- The query string contains the **recipient's email address**, so the attacker can tell which target clicked.
- The SafeLinks wrapper was present, which shows that URL rewriting alone did not block this link.

## 4. Verdict

**Phishing, most likely credential harvesting.** The evidence for it:

1. Sender domain unrelated to Amazon, with a misspelled display name.
2. Urgent "account locked" lure with a "Review Account" button.
3. The button leads to a look-alike domain (`amaozn…`), not `amazon.com`.
4. The link carries the victim's address as a tracking token.
5. Authentication passes only for the attacker's own domain.

## 5. Recommended actions

- Delete or quarantine the message and block `zyevantoby[.]cn` and `zzyuchengzhika[.]cn`.
- Search mail logs for other recipients of the same sender and for any clicks on the link.
- If a user clicked or entered credentials, reset the password and review recent sign-ins.
- Tell users that a passing SPF/DKIM result is not proof an email is genuine.

## 6. Indicators of compromise (defanged)

| Type | Value |
|------|-------|
| Sender address | `amazon@zyevantoby[.]cn` |
| Sender domain | `zyevantoby[.]cn` |
| Sending IP | `45.156.23.138` |
| HELO host | `mta0[.]zyevantoby[.]cn` |
| Phishing URL | `hxxps://amaozn[.]zzyuchengzhika[.]cn/?mailtoken=…` |
| Message-ID | `<000756bf516d$9bad2034$6e61f7fb$@vinuqou>` |

## 7. Not verified

- I did not capture what the landing page showed, so "credential harvesting" is the most likely purpose rather than a confirmed one.
- I did not look up the domains' registration age.
