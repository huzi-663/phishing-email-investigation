# Case 2: "Website contact form submission" (spam via an abused web form)

**Platform:** LetsDefend (Phishing Analysis challenge)
**Classification reached:** Spam / scam link-bait, not a targeted attack

## 1. What was received

Screenshot: [01-bounce-email.png](../screenshots/case2-contact-form-spam/01-bounce-email.png)

The mailbox owner received a delivery-failure notice with a `.eml` attachment inside it.

| Field | Value |
|-------|-------|
| Outer subject | `Website contact form submission` |
| Inner message from | `Mail Delivery System <Mailer-Daemon@se7-syd.hostedmail.net.au>` |
| Inner message sent | 18 March 2021 04:14 |
| Inner subject | `Undeliverable: Website contact form submission` |
| Failed recipient | `kinnar1975@yahoo[.]co[.]uk` |
| Failure text | `554 30 Sorry, your message to kinnar1975@yahoo.co.uk cannot be delivered. This mailbox is disabled` |

The visible email is a bounce. The interesting content is the original message it carries.

## 2. The original message

Screenshot: [04-original-submission.png](../screenshots/case2-contact-form-spam/04-original-submission.png)

The attached original is a copy of a website form submission:

- First name and last name are both `Robertbiolo`.
- Email address: `kinnar1975@yahoo[.]co[.]uk`; mobile: `85471397431`.
- **Booking Date `1977-11-10`** and **Booking Time `RobertbioloXE`**, which are not valid values for a booking form.
- **Services Required** is empty.
- Free text: *"Good earnings from $6500 per day"* followed by two blogspot links (defanged):
  - `hxxps://35000usdperwwekpodf[.]blogspot[.]sg/?p=9swg…`
  - `hxxps://35000usdperwwekpodf[.]blogspot[.]co[.]il/?o=0hnd`

Junk field values, a nonsense booking time and a get-rich-quick link are typical of automated spam submitted to contact forms rather than a real customer.

## 3. Header analysis

Screenshot: [02-received-header.png](../screenshots/case2-contact-form-spam/02-received-header.png)

```
Received: from c5s2-1e-syd.hosting-services.net.au ([103.9.171.10])
        by se7-syd.hostedmail.net.au with esmtps (TLSv1.2 …) (Exim 4.92)
        id 1lMk2r-0007vB-6O
        for kinnar1975@yahoo.co.uk; Thu, 18 Mar 2021 15:14:06 +1100
Received: from markgard by c5s2-1e-syd.hosting-services.net.au with local (Exim 4.94)
        id 1lMk2m-002w3b-NT …
```

- The message was submitted **locally** on the web host (`from markgard by … with local`) and then relayed from `103.9.171.10`. The time 15:14:06 +1100 equals 04:14:06 UTC, matching the bounce's "sent 04:14".
- This is consistent with a website's contact-form script running under a hosting account, not with a spoofed external sender. This is my inference from the `Received` lines.
- The `To` address on the form copy is the same address typed into the form's *Email Address* field. That suggests the form emails whatever address is entered, which would let a bot use it to send its text to arbitrary recipients.

## 4. IP and domain lookups

Screenshots: [03-whois-sending-ip.png](../screenshots/case2-contact-form-spam/03-whois-sending-ip.png), [05-whois-blogspot.png](../screenshots/case2-contact-form-spam/05-whois-blogspot.png)

| Lookup | Result |
|--------|--------|
| `103.9.171.10` | Sydney, Australia; Synergy Wholesale Pty Ltd; ASN AS45638; resolves to `c5s2-1e-syd.hosting-services.net.au`; 3 websites use this address |
| `blogspot.sg` | Registrar MarkMonitor; created 2010-09-15; name servers `ns1–ns4.google.com`; IP `142.250.69.169`, Google LLC, AS15169 |

- The sending IP belongs to a legitimate Australian hosting provider, so blocking it would not be a precise response.
- WHOIS for `blogspot.sg` describes Google, not the spammer. This matches the free-subdomain abuse described in the LetsDefend "Additional Techniques" lesson: the registration data of the platform hides the owner of the individual page.

## 5. Verdict

**Spam / scam link-bait.** Evidence: nonsense form values, a "$6500 per day" lure, links to a disposable free-blog subdomain, and delivery through a form on a shared host.

It is lower risk than Cases 1 and 3 (no attachment, no credential request), but still worth acting on because the form is being abused.

## 6. Recommended actions

- Add CAPTCHA, rate limiting and server-side validation (for example, valid dates) to the contact form.
- Stop the form sending copies to the address entered by the submitter.
- Do not click the blogspot links; report them to the platform.
- Report the abuse to the hosting provider's abuse contact if the site owner is not the one running the form.

## 7. Not verified

- I did not capture what the linked page contained, so I cannot say whether it was a scam page, malware or something else.
- That a bot (rather than a person) submitted the form is inferred from the content, not confirmed.
