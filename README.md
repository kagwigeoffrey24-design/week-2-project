# Footprinting and Reconnaissance Lab Report

13 November 2026

Footprinting networkwalks.com with six Kali Linux tools shows a WordPress site on HostGator, behind a ModSecurity firewall, with privacy-protected registration and unsigned DNS. A final Zenmap ping scan maps eight live hosts on the local network.

## Scope and tools

The lab footprints one target, the domain networkwalks.com, from a Kali Linux virtual machine in Oracle VirtualBox on 13 November 2026. Footprinting collects information about a target before any attack; reconnaissance adds direct queries to the target's DNS and web servers. Run these tools only against systems you own or have written permission to test.

| Tool | What it gathers | Type |
| --- | --- | --- |
| whois | Domain registration and name server records | Passive |
| nslookup | The IP address the domain resolves to | Passive |
| dnsrecon | SOA, NS, MX, A, TXT and SRV records | Active |
| whatweb | Web server, CMS, plugins and libraries | Active |
| curl -I | HTTP response headers | Active |
| wafw00f | Presence and brand of a web application firewall | Active |
| Zenmap | Live hosts on the local network | Active |

## 1. WHOIS lookup

Running `whois networkwalks.com` shows a domain registered through GoDaddy, hidden behind a privacy service and delegated to HostGator name servers.

![whois output for networkwalks.com](images/01-whois.png)

*Figure 1: whois output for networkwalks.com*

| Field | Value |
| --- | --- |
| Registrar | GoDaddy.com, LLC (IANA ID 146) |
| Created | 6 November 2019 |
| Last updated | 12 November 2025 |
| Expires | 6 November 2027 |
| Name servers | NS6135.HOSTGATOR.COM, NS6136.HOSTGATOR.COM |
| Registrant | Registration Private, Domains By Proxy, LLC (Tempe, Arizona, US) |
| Domain locks | clientTransferProhibited, clientUpdateProhibited, clientRenewProhibited, clientDeleteProhibited |
| DNSSEC | Unsigned |

The output holds two records. The registry (Verisign) record gives the dates, locks and name servers. The registrar record adds the registrant detail: Domains By Proxy replaces the owner's name, address and email with a contact web form, and it lists two further name servers, NS29.DOMAINCONTROL.COM and NS30.DOMAINCONTROL.COM.

Why it matters: privacy protection means no personal registrant data is exposed, the four client locks guard against unauthorised transfer or deletion, and unsigned DNSSEC means DNS answers for the domain cannot be cryptographically verified.

## 2. DNS resolution

Running `nslookup networkwalks.com` resolves the domain to the IP address 192.232.216.135.

![nslookup output for networkwalks.com](images/02-nslookup.png)

*Figure 2: nslookup output for networkwalks.com*

The query went to the local resolver at 192.168.100.1 on port 53. The answer is marked non-authoritative, meaning that resolver is not the authority for the domain and answered from its cache or by asking other servers.

Why it matters: this single address is the starting point for every later step, and dnsrecon returns it for both the A and MX records, and WhatWeb reports it for the site.

## 3. DNS enumeration

Running `dnsrecon -d networkwalks.com` in its default standard mode recovered the domain's authority, address, mail, text and service records in about 16 seconds.

![dnsrecon output for networkwalks.com](images/03-dnsrecon.png)

*Figure 3: dnsrecon output for networkwalks.com*

| Record | Result |
| --- | --- |
| SOA | ns6135.hostgator.com (50.87.144.87) |
| NS | ns6135.hostgator.com (50.87.144.87), ns6136.hostgator.com (192.232.216.131) |
| A | networkwalks.com → 192.232.216.135 |
| MX | mail.networkwalks.com → 192.232.216.135 |
| TXT | Google site verification record; SPF `v=spf1 +a +mx +ip4:50.87.144.87 +include:websitewelcome.com ~all` |
| SRV | _autodiscover._tcp → cpanelemaildiscovery.cpanel.net, 8 addresses in 184.94.203.x and 184.94.204.x, port 443 |
| DNSSEC | No answer to the DNSSEC query |

Both name servers disclose the BIND version 9.16.23-RH, which lets an attacker look up known vulnerabilities for that release. The A and MX records share one address, so web and mail run on the same server, and the autodiscover records point to cPanel-managed hosting.

Why it matters: the SPF record ends in ~all (soft fail), so mail from unlisted servers is flagged but not necessarily rejected. The missing DNSSEC answer matches the unsigned status seen in WHOIS.

## 4. Web technology fingerprinting

Running `whatweb networkwalks.com` identifies the site as WordPress 7.1.4 on Apache, titled "Networkwalks Academy" and served from 192.232.216.135 in the United States.

![whatweb output for networkwalks.com](images/04-whatweb.png)

*Figure 4: whatweb output for networkwalks.com*

| Detected | Detail |
| --- | --- |
| Web server | Apache |
| CMS | WordPress 7.1.4 |
| Plugin | WordPress Download Manager 3.3.76 |
| Libraries | jQuery 3.7.1, HTML5, Bootstrap (reported as 7.1.4) |
| Analytics | Google Tag Manager |
| Contact email | info@networkwalks.com |
| Cookie | __wpdm_client (HttpOnly) |
| Redirect | http://networkwalks.com to https://networkwalks.com/ (301 Moved Permanently) |
| Uncommon headers | permissions-policy, x-redirect-by, referrer-policy, x-endurance-cache-level, x-nginx-cache, link |

WhatWeb returned three results: the HTTP address redirects to HTTPS, and both HTTPS requests answer 200 OK.

Why it matters: the CMS and plugin versions are the most useful result, because they can be compared with published vulnerability lists, and the exposed email address is a phishing target. WhatWeb reports Bootstrap 7.1.4, the same string as the WordPress version, so that value is likely a detection error and needs manual checking.

## 5. HTTP response headers

Running `curl -I https://networkwalks.com` returned 200 OK on 13 November 2026 and exposed the hosting platform through several response headers.

![curl -I output for https://networkwalks.com](images/05-curl-headers.png)

*Figure 5: curl -I output for https://networkwalks.com*

| Header | What it reveals |
| --- | --- |
| Server: Apache | Web server software, with no version number |
| Link | The WordPress REST API at /wp-json/ and page ID 53 |
| Set-Cookie: __wpdm_client | Download Manager cookie, flagged secure and HttpOnly |
| Permissions-Policy | Private state token permissions for Google, reCAPTCHA, Cloudflare and hCaptcha, which points to CAPTCHA use |
| Referrer-Policy | no-referrer-when-downgrade |
| X-Endurance-Cache-Level: 0 | Endurance caching layer used by HostGator-managed WordPress hosting |
| X-nginx-cache: WordPress | An nginx cache sits in front of Apache |
| Content-Type | text/html; charset=UTF-8 |

Why it matters: the Server header hides the Apache version, which is good practice, but the Link header still exposes the WordPress REST API. None of the captured headers is Strict-Transport-Security, Content-Security-Policy, X-Frame-Options or X-Content-Type-Options, so those protections are not visible in this response.

## 6. Web application firewall detection

Running `wafw00f networkwalks.com` (version 2.4.2) detected a ModSecurity (SpiderLabs) web application firewall in front of https://networkwalks.com, using only 2 requests.

![wafw00f output for networkwalks.com](images/06-wafw00f.png)

*Figure 6: wafw00f output for networkwalks.com*

A WAF filters malicious requests such as SQL injection and cross-site scripting.

Why it matters: intrusive scans against this site would likely be blocked or logged, so a tester must scope them accordingly. For the site owner, the result confirms the firewall is active and identifiable from outside.

## 7. Local network discovery with Zenmap

A Zenmap ping scan of 192.168.100.0/24 found 8 of 256 addresses up in 41.15 seconds. The scan used the Ping scan profile (`nmap -sn 192.168.100.0/24`) with Nmap 7.993 on 13 November 2026 at 22:17 (UTC+3).

![Zenmap ping scan output for 192.168.100.0/24](images/07-zenmap-scan.png)

*Figure 7: Zenmap ping scan of 192.168.100.0/24*

| Host | Latency | MAC address | Vendor | Likely role |
| --- | --- | --- | --- | --- |
| 192.168.100.1 | 0.020 s | D8:6D:17:05:31:A2 | Huawei Technologies | Router; also the DNS resolver queried in the nslookup step |
| 192.168.100.5 | 0.095 s | 62:97:7C:10:80:53 | Unknown | Randomised MAC, typical of a phone or laptop |
| 192.168.100.7 | 0.093 s | 88:28:7D:0A:03:27 | AltoBeam (China) | Device with an AltoBeam network chipset |
| 192.168.100.55 | 0.12 s | 32:F9:8C:25:ED:75 | Unknown | Randomised MAC, typical of a phone or laptop |
| 192.168.100.78 | 0.075 s | 26:D7:3B:0B:09:49 | Unknown | Randomised MAC, typical of a phone or laptop |
| 192.168.100.121 | 0.16 s | 0E:C9:F3:2D:BD:D8 | Unknown | Randomised MAC, typical of a phone or laptop |
| 192.168.100.124 | 0.13 s | 2A:48:E9:83:ED:25 | Unknown | Randomised MAC, typical of a phone or laptop |
| 192.168.100.31 | Not shown | Not shown | Not shown | Most likely the scanning machine itself, since Nmap shows no MAC or latency for its own address |

The -sn option skips the port scan and only checks which hosts respond. On a local subnet Nmap does this with ARP requests, which is why MAC addresses and vendors appear. Five hosts (192.168.100.5, .55, .78, .121 and .124) show an unknown vendor and a MAC whose first byte marks it as locally administered, which is typical of phones and laptops using a randomised private Wi-Fi address.

The Topology tab draws the same result as a map. The scanning machine (localhost) sits at the centre and each responding host connects to it directly, which fits a flat local subnet.

![Zenmap topology view of the eight hosts](images/08-zenmap-topology.png)

*Figure 8: Zenmap topology view of 192.168.100.0/24*
