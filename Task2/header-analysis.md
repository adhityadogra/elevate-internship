
## 1. Suspicious Sending IP Address
**IP:** 91.212.89.44  
- Not associated with PayPal, which uses validated, encrypted SMTP servers.
- Hosted on foreign VPS hosting (often used for phishing).
- No reverse DNS → indicates misconfigured / malicious server.


## 2. SPF Failure (softfail)
- The domain paypalsecure-notice.com did NOT authorize this server to send emails.
- Legit PayPal emails always pass SPF.


## 3. DKIM Missing
- PayPal digitally signs all their emails.
- Absence of DKIM = sender cannot be trusted.


## 4. DMARC Failure
- Domain policy rejects the email.
- Indicates sender identity is spoofed.


## 5. Mismatch Between From and Reply-To
- From: alert@paypalsecure-notice.com  
- Reply-To: noreply@paypal.com  

Attackers often use a legitimate Reply-To address to mislead users into replying safely.


## 6. Untrusted “Received” Path
- “unknown” indicates missing rDNS.
- PayPal servers always have valid DNS & SSL configuration.


## 7. Timestamp & Server Location Mismatch
- Email timestamp matches local time, but sender’s IP is registered in Eastern Europe.
- PayPal does not operate mail servers there.


## ✔ Conclusion
The PayPal email header contains multiple red flags:
- Unauthorized sending IP  
- SPF softfail  
- No DKIM  
- DMARC fail  
- Domain spoofing  
- Suspicious mail path  
- Fake Reply-To behavior  