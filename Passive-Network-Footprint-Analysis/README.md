============================================================
 NETWORK FOOTPRINT REPORT
============================================================

Analyst:        Gabriella Smriti
Analysis Date:  06-08-2026
Engagement:     Passive Reconnaissance of www.qua.clothing
Methodology:    nslookup, WHOIS, DNSDumpster, BuiltWith
                (Passive OSINT Reconnaissance)

------------------------------------------------------------
 1. TARGET SUMMARY
------------------------------------------------------------

Domain:          www.qua.clothing
Description:     Online fashion and clothing retailer.
Reason chosen:   Selected as a publicly accessible e-commerce
                 website to demonstrate passive network
                 footprint analysis using OSINT techniques.
Scope:           Passive reconnaissance only — public sources
                 only, no scanning, no probing, and no
                 interaction with target infrastructure.

------------------------------------------------------------
 2. EXECUTIVE SUMMARY
------------------------------------------------------------

A passive reconnaissance assessment was conducted on
www.qua.clothing using publicly available information.
DNS records, domain registration details, certificate
transparency data, and web technologies were examined to
understand the organization's public network footprint.
The target utilizes managed hosting services and modern web
technologies. No critical information exposure or obvious
misconfigurations were identified through passive
reconnaissance.

------------------------------------------------------------
 3. DNS RECORDS
------------------------------------------------------------

A record(s):       23.227.38.74
MX record(s):     Not identified
NS record(s):      Not identified
TXT record(s):     Not identified
Other notable:     No additional publicly accessible DNS
                   records of significance were identified.

------------------------------------------------------------
 4. WHOIS
------------------------------------------------------------

Registrar:         GoDaddy.com, LLC
Registration date: 2018-06-03T17:33:56.63Z
Expiration date:   2029-06-03T17:33:56.63Z
Registrant:        Domains By Proxy, LLC
Contact email:     https://www.godaddy.com/whois/results.aspx?domain=qua.clothing&action=contactDomainOwner
Domain age:        Approximately 8 years

------------------------------------------------------------
 5. CERTIFICATE TRANSPARENCY
------------------------------------------------------------

Total certs issued: Not determined
CA used most:       Not identified
Subdomains found:   Not identified
Notable findings:   No publicly exposed subdomains or
                    certificate-related anomalies were
                    identified during passive analysis.

------------------------------------------------------------
 6. TECHNOLOGY PROFILE
------------------------------------------------------------

Server software:    Amazon API Gateway
CMS/framework:      Shopify
Analytics:          Klaviyo
Hosting provider:   Shopify
Other tech:     jQuery 3.5.1, Klaviyo email marketing

------------------------------------------------------------
 7. OBSERVATIONS
------------------------------------------------------------

The target website is hosted on a managed e-commerce
infrastructure and employs privacy protection for domain
registration. Technology profiling indicates the use of
Shopify and third-party marketing services. Passive
reconnaissance did not reveal publicly accessible
development environments or other notable exposures.

------------------------------------------------------------
 8. RECOMMENDATIONS
------------------------------------------------------------

If briefing the target's security team:

  [ ] Periodically review DNS records and remove obsolete
      entries that are no longer required.

  [ ] Continue monitoring Certificate Transparency logs for
      unauthorized certificate issuance.

  [ ] Regularly audit third-party integrations and maintain
      current security best practices for the hosted
      e-commerce platform.

============================================================
 END OF REPORT
============================================================
