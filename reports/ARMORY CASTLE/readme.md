# Threat Analysis: ARMORY CASTLE exploits BeyondTrust Remote Support (CVE-2026-102764)

## Executive summary

GTIG and Mandiant attribute zero-day exploitation of CVE-2026-102764, an unauthenticated arbitrary file-upload bug in BeyondTrust Remote Support up to 26.2.3, to ARMORY CASTLE (formerly UNC5221), a suspected PRC-nexus espionage actor. Exploitation began in late August 2026; BeyondTrust patched SaaS tenants on October 9 and disclosed on October 15. From one webshell foothold the actor reached root through a SUID shell, made root survive reboot by editing the vendor sudoers template, tried to dump the appliance credential vault, and used stolen admin access to drive the product's own support sessions into internal endpoints. A SOCKS5-over-WebSocket tunneler was hidden behind the appliance's HAProxy, and logs were wiped repeatedly. Overall confidence in the intrusion narrative is High; victimology is Low because the report gives none. **IOC set is incomplete by design:** only two SHA-256 hashes are public, the staging webshell has no hash, and the article publishes no adversary IPs or domains (any further IOCs are in a GTI collection for registered users; its contents were not checked). VirusTotal enrichment was skipped for lack of an API key.

## Attribution & Diamond Model

**Adversary.** ARMORY CASTLE (formerly UNC5221), suspected PRC-nexus espionage  
Evidence: "suspected PRC-nexus espionage threat actor (formerly tracked as UNC5221)"  
Confidence: High (vendor attribution); Medium (state nexus, hedged as 'suspected')

**Capability.** CVE-2026-102764 zero-day; SAWFLY; BARECLAW; unrecovered staging shell; abuse of bt-secrets, bt-sysconfig, haproxy.conf  
Evidence: "newly identified custom malware, the SAWFLY webshell and the BARECLAW tunneler"  
Confidence: High

**Infrastructure.** No external C2 IPs or domains published. Victim appliance used as the pivot; inbound via /uidchanarge through HAProxy.  
Evidence: "routes the incoming web stream locally (127.0.0.1 / localhost) to TCP port 19800"  
Confidence: High for on-box infrastructure; none for adversary-owned infrastructure

**Victim.** One organization running self-hosted or appliance BeyondTrust RS; sector and geography not disclosed  
Evidence: "During an incident response engagement"  
Confidence: Low (victimology absent)

**Meta.** Exploitation late August 2026. SaaS patched 2026-10-09. Public disclosure 2026-10-15. Report says the actor has been active since October 2023.

## Cyber Kill Chain

| Phase | Behavior | IDs | Confidence |
|---|---|---|---|
| Reconnaissance | No evidence in report | None | n/a |
| Weaponization | Zero-day exploit for the CVE (implied) | none | Medium |
| Delivery | HTTP to internet-facing appliance | T1190 | High |
| Exploitation | Arbitrary file upload, CVE-2026-102764 | T1190 | High |
| Installation | Webshells, SUID shell, boot script, sudoers | T1505.003, T1548.001, T1037, T1548.003, T1027, T1036.005, T1105 | High (T1036.005, T1105 Medium) |
| Command & Control | SAWFLY HTTP C2; BARECLAW via HAProxy | T1071.001, T1573.001, T1132.001, T1090.001, T1572 | High (T1132.001 Medium) |
| Actions on Objectives | Vault dump, admin abuse, endpoint collection, log wiping | T1555, T1078, T1098, T1219, T1005, T1083, T1041, T1059.004, T1685.006, T1070.004 | High (T1083, T1041 Medium) |

Full evidence for each ID is in the details list below.

## ATT&CK & ATLAS technique mapping

Mapped against ATT&CK Enterprise v20.0. ATLAS: not applicable; nothing in this intrusion targets an AI/ML system.

| # | Technique | Confidence |
|---|---|---|
| 1 | T1190 Exploit Public-Facing Application | High (0.95) |
| 2 | T1505.003 Web Shell | High (0.95) |
| 3 | T1027 Obfuscated Files or Information | High (0.85) |
| 4 | T1132.001 Standard Encoding | Medium (0.65) |
| 5 | T1573.001 Symmetric Cryptography | High (0.9) |
| 6 | T1071.001 Web Protocols | High (0.9) |
| 7 | T1059.004 Unix Shell | High (0.9) |
| 8 | T1548.001 Setuid and Setgid | High (0.95) |
| 9 | T1036.005 Match Legitimate Resource Name or Location | Medium (0.6) |
| 10 | T1555 Credentials from Password Stores | High (0.85) |
| 11 | T1037 Boot or Logon Initialization Scripts | High (0.85) |
| 12 | T1548.003 Sudo and Sudo Caching | High (0.95) |
| 13 | T1685.006 Clear Linux or Mac System Logs | High (0.95) |
| 14 | T1070.004 File Deletion | High (0.9) |
| 15 | T1078 Valid Accounts | High (0.9) |
| 16 | T1098 Account Manipulation | High (0.95) |
| 17 | T1219 Remote Access Tools | High (0.85) |
| 18 | T1083 File and Directory Discovery | Medium (0.6) |
| 19 | T1005 Data from Local System | High (0.85) |
| 20 | T1041 Exfiltration Over C2 Channel | Medium (0.6) |
| 21 | T1090.001 Internal Proxy | High (0.95) |
| 22 | T1572 Protocol Tunneling | High (0.9) |
| 23 | T1105 Ingress Tool Transfer | Medium (0.65) |

1. **T1190 Exploit Public-Facing Application** (Initial Access). Zero-day exploitation of CVE-2026-102764 in BeyondTrust Remote Support. Evidence: "exploited this vulnerability as a zero-day, in late August 2026". Stated outright, with CVE and timeframe.
2. **T1505.003 Web Shell** (Persistence). Unrecovered staging webshell, then SAWFLY written to the Laravel web root. Evidence: "the file system recorded the creation of the SAWFLY webshell at the web root path". Named malware, path and file-system timestamp.
3. **T1027 Obfuscated Files or Information** (Stealth). SAWFLY is obfuscated PHP with an obfuscated trigger parameter. Evidence: "SAWFLY (mangoapi.php) is an obfuscated, lightweight PHP webshell". Stated; sub-technique not determinable from text.
4. **T1132.001 Standard Encoding** (Command and Control). Base32 wrapping of SAWFLY C2 traffic. Evidence: "a custom Base32 transport layer". Report says 'custom', but the YARA string is the standard RFC 4648 alphabet, so .001 over .002 is tentative.
5. **T1573.001 Symmetric Cryptography** (Command and Control). RC4 with a hardcoded 32-byte key (SAWFLY); token-derived XOR stream (BARECLAW). Evidence: "decrypts it using RC4 with a hardcoded 32-byte key". Cipher and key handling stated for both tools.
6. **T1071.001 Web Protocols** (Command and Control). C2 over HTTP POST to SAWFLY; WebSocket to BARECLAW through HAProxy. Evidence: "The webshell inspects incoming HTTP POST requests for the obfuscated parameter _c94mfe". Transport stated.
7. **T1059.004 Unix Shell** (Execution). sh -c log deletion and a bash persistence script. Evidence: "/usr/sbin/sh -c 'rm -f /home/bomgar/log/bt-secrets.log ...'". Recovered commands shown verbatim.
8. **T1548.001 Setuid and Setgid** (Privilege Escalation). Copied /bin/sh to /usr/bin/dbus-authd, chowned to root, set SUID. Evidence: "copied the system shell executable (/bin/sh) to the file /usr/bin/dbus-authd". Stated with file path and permission change.
9. **T1036.005 Match Legitimate Resource Name or Location** (Stealth). SUID shell named to resemble a D-Bus component in /usr/bin. Evidence: "/usr/bin/dbus-authd". Analyst inference from the name; the report never calls it masquerading.
10. **T1555 Credentials from Password Stores** (Credential Access). Dumping the appliance vault with the native bt-secrets CLI. Evidence: "/ns/sbin/bt-secrets get vault". Attempt is stated; whether the dump succeeded is not.
11. **T1037 Boot or Logon Initialization Scripts** (Persistence / Privilege Escalation). zz-root-persist dropped in the vendor post_boot.d startup directory. Evidence: "created the /home/bomgar/sbin/post_boot.d directory, which is reserved for scripts executed automatically at system startup". Behavior stated; parent ID used because a vendor post-boot hook is not a standard RC script.
12. **T1548.003 Sudo and Sudo Caching** (Privilege Escalation). NOPASSWD: ALL appended to sudoers.template, rebuilt via bt-sysconfig. Evidence: "appends '%SITE_SERVICE_ACCOUNT% ALL=(ALL) NOPASSWD: ALL' to the template". Script contents shown verbatim.
13. **T1685.006 Clear Linux or Mac System Logs** (Defense Impairment). rm -f of /var/log/messages and /ns/log/* appliance logs. Evidence: "rm -f /ns/log/auth.log ... /var/log/messages". Recovered command; T1070.002 is revoked in ATT&CK v20 and points here.
14. **T1070.004 File Deletion** (Stealth). Deleted bt-secrets.log, rotated archives and /tmp/sshauth.*. Evidence: "rm -f /home/bomgar/log/bt-secrets.log /home/bomgar/log/bt-secrets.log.*". Recovered command.
15. **T1078 Valid Accounts** (Stealth / Persistence / Privilege Escalation / Initial Access). Logged into /login with a compromised Administrator account. Evidence: "leveraged the Administrator account to log into the web administrative portal". Stated, with syslog login event.
16. **T1098 Account Manipulation** (Persistence / Privilege Escalation). Raised Jump Item and Team roles from No Access to Administrator. Evidence: "upgrading both local Jump Items and Team permissions from No Access to Administrator". Stated, with user_changed syslog event.
17. **T1219 Remote Access Tools** (Command and Control). Used the product's own support sessions to reach internal endpoints. Evidence: "establish a remote support session to target internal endpoints". Stated; the legitimate tool is the lateral-movement channel.
18. **T1083 File and Directory Discovery** (Discovery). Requested full file-system access on reached endpoints. Evidence: "request and obtain full file-system access". Browsing is implied by the access request, not described.
19. **T1005 Data from Local System** (Collection). Pulled documents such as software inventories from user desktops. Evidence: "download and exfiltrate sensitive internal documents". Stated.
20. **T1041 Exfiltration Over C2 Channel** (Exfiltration). Exfiltration through the Remote Support file transfer service. Evidence: "native BeyondTrust Remote Support file transfer service to download and exfiltrate". Exfil stated; treating the RS channel as C2 is an analyst mapping choice.
21. **T1090.001 Internal Proxy** (Command and Control). BARECLAW SOCKS5 on 127.0.0.1:19800, exposed through an HAProxy ACL. Evidence: "server websocks5srv 127.0.0.1:19800". Config shown verbatim.
22. **T1572 Protocol Tunneling** (Command and Control). SOCKS5 carried inside WebSocket. Evidence: "a SOCKS5 proxy service carried over the WebSocket transport". Stated.
23. **T1105 Ingress Tool Transfer** (Command and Control). BARECLAW binary present at /tmp/ingredi_ws. Evidence: "/tmp/ingredi_ws --listen 19800". How the binary arrived is not described; inferred from its presence.

## Incidents / clusters

| ID | Cluster | Confidence |
|---|---|---|
| INC-1 | BeyondTrust RS appliance intrusion | High (0.9) |

- INC-1: one Mandiant engagement described end to end. GTIG's forecast of post-disclosure mass exploitation is an assessment, not an observed incident, so it is not a cluster here.

## Indicators of Compromise

### File hashes (SHA-256)

| File | Family | SHA-256 | VT |
|---|---|---|---|
| mangoapi.php | SAWFLY | `dc14e215269a93fdbc4c1a80b984c23faf7af0911c6dbb85309796a6f2ae95fb` | skipped |
| ingredi_ws | BARECLAW | `1f19b9a27d79c11bda00a1e8faf74a7fdd683d38ccef1b60df2fd0307e3aa462` | skipped |
| app_84304470%2Ephp | Staging webshell | not published | n/a |

### CVEs

| CVE | Context |
|---|---|
| CVE-2026-102764 | Exploited as zero-day in this intrusion |
| CVE-2023-46805 | Historical: prior ARMORY CASTLE mass exploitation (Ivanti), context only |
| CVE-2024-21887 | Historical: prior ARMORY CASTLE mass exploitation (Ivanti), context only |

### Host file paths

| Path | Context |
|---|---|
| `/usr/bin/dbus-authd` | SUID-root copy of /bin/sh |
| `/home/bomgar/sbin/post_boot.d/zz-root-persist` | Boot persistence script |
| `/ns/config/sudoers.template` | Modified: NOPASSWD entry appended |
| `/ns/config/haproxy.conf` | Modified: acl wswsws / backend webskd3 |
| `/tmp/ingredi_ws` | BARECLAW binary |
| `/%SITE_SERVICE_ACCOUNT%/ingredi/app/laravel/public/mangoapi.php` | SAWFLY location (dir + filename joined by analyst) |
| `/home/bomgar/log/bt-secrets.log` | Deleted after vault access |

### HTTP, config and command artifacts

| Type | Value | Context |
|---|---|---|
| uri | `/app_84304470%2Ephp` | POST target of the staging webshell |
| http_param | `_c94mfe` | SAWFLY POST parameter; absent -> 404 |
| uri | `/uidchanarge` | BARECLAW WebSocket path routed by HAProxy |
| port | `19800/tcp (localhost)` | BARECLAW listener |
| config_string | `acl wswsws path /uidchanarge` | HAProxy ACL added |
| config_string | `backend webskd3 / server websocks5srv` | HAProxy backend added |
| command | `/ns/sbin/bt-secrets get vault` | Vault dump (3 syntax variants) |
| command | `/ns/sbin/bt-sysconfig --no-restart misc` | Forces sudoers rebuild from template |

### Network indicators

None published in the article. No adversary IPs, domains or emails.

### Malware and actors

| Name | Type | ATT&CK |
|---|---|---|
| SAWFLY | PHP webshell | none |
| BARECLAW | C SOCKS5/WebSocket tunneler | none |
| ARMORY CASTLE (fka UNC5221) | Threat actor | no G-ID; see C0029 |

## Enrichment findings

**MITRE ATT&CK actor lookup.** Neither ARMORY CASTLE nor UNC5221 resolves to an ATT&CK intrusion-set (true negative). UNC5221 appears in ATT&CK campaign **C0029 Cutting Edge** (UNC5221/UTA0178 and UNC5325, Ivanti Connect Secure zero-days, 2023-12-01 to 2024-02-01). Technique overlap with this report: T1005, T1059.004, T1070.004, T1105, T1190, T1505.003, T1572, T1685.006 (T1059.004 and T1685.006 match C0029 only at the parent level). These are generic edge-appliance techniques, so the overlap shows consistency, not independent attribution.

**VirusTotal.** Skipped: `VT_API_KEY` not set. Two full SHA-256 values were eligible; nothing was sent.

## Analyst notes & gaps

- **Revoked ID check.** T1070.002 was submitted as a canary. ATT&CK v20 revoked it in favour of T1685.006, but `mitre_enrich.py` passed it as valid because it doesn't filter `revoked` objects. Fix the script: skip objects with `revoked: true` or `x_mitre_deprecated: true` when building `tech_ids`.
- **Vault dump outcome unknown.** The report says the actor attempted to harvest credentials. It doesn't say the dump succeeded. Treat every vault credential as exposed anyway, since the actor had root.
- **SUID /bin/sh needs -p.** Bash and recent dash drop the effective UID unless run with `-p`. The report doesn't show how `dbus-authd` was invoked, or which shell `/bin/sh` is on the appliance. Hunting for `dbus-authd -p` in process telemetry is a reasonable guess, not a published IOC.
- **SecOps rule names don't match the narrative.** Curl-to-/tmp and base64-to-shell rules are listed, but no curl or base64 activity is described. Either steps were omitted or those rules caught other activity. The report doesn't say which.
- **BARECLAW YARA precedence.** `uint32(0) == 0x464c457f and (5 of ($s*)) or ($b_xorshift and (3 of ($s*)))` evaluates the second branch without the ELF check, so it can match non-ELF data. Possibly intended for memory hunting; undocumented either way.
- **Base32 sub-technique.** The report calls the encoding custom; the YARA alphabet is standard RFC 4648. T1132.001 is used, tentatively.
- **Detection surface.** Mandiant says customers can't audit the appliance host file system. Practical telemetry is syslog (`user_changed`, `login`), reverse-proxy or WAF URI logs (`/uidchanarge`, unknown `.php`), and gaps in syslog forwarding.
- **Not verified here.** CVE-2026-102764's CVSS, NVD entry, KEV status and the BT26-05 version range were not checked against primary sources in this run.
- **Timeline gap.** SaaS was patched six days before disclosure. Whether self-hosted customers got private notice is not stated.
- **ATT&CK v20 tactics.** v20 replaced Defense Evasion with Stealth and Defense Impairment. Tactic labels here are read from the v20 data.
- **STIX bundle.** Built with relationships, TLP:CLEAR, deterministic IDs and a report object; validated with stix2-validator.
- **Removed by analyst:** `sudoers.template` (filename caught as a domain) and `127.0.0.1` (HAProxy loopback). Excluded URL-path hash: the GTI collection ID.

## Sources

- [ARMORY CASTLE Exploits BeyondTrust, GTIG/Mandiant, 2026-10-15](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust)
- [BeyondTrust advisory BT26-05](https://www.beyondtrust.com/trust-center/security-advisories/bt26-05) (linked from the report, not fetched)
- [MITRE ATT&CK C0029 Cutting Edge](https://attack.mitre.org/campaigns/C0029)
- MITRE ATT&CK Enterprise STIX v20.0 (attack-stix-data, fetched 2026-10-16)
