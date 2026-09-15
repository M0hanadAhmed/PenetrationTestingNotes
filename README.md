# Penetration Testing Notes

My personal offensive security learning journey — hands-on writeups and raw notes from the **TryHackMe Jr Penetration Tester Learning Path**, plus ongoing CTF and bug bounty work.

---

## Structure

- [`TryHackMe/Jr-Penetration-Tester/`](./TryHackMe/Jr-Penetration-Tester/) — room-by-room writeups from the Jr Penetration Tester path
- [`TryHackMe/Jr-Penetration-Tester/Challenges/`](./TryHackMe/Jr-Penetration-Tester/) — end-to-end challenge writeups (multi-step engagements: enumeration → exploitation → privilege escalation)

Each writeup follows the same format: **What This Room Is About / Tools Used / What I Learned / Key Commands / Key Takeaway** — no flags or direct answers, so it stays useful as a learning reference rather than a walkthrough.

---

## Progress

### Network Reconnaissance & Nmap
| # | Room |
|---|------|
| 5–9 | Recon Frameworks, Passive/Active Recon, Protocols & Servers |
| 10–13 | Nmap: Host Discovery, Basic Scans, Advanced Port Scans, Post Port Scans |

### Web Application Security Fundamentals
| # | Room |
|---|------|
| 14 | Walking an Application |
| 15 | Content Discovery |
| 16 | Modern Web Stacks |
| 17 | Web Server Attacks I |
| 18 | Web Server Attacks II |

### Burp Suite
| # | Room |
|---|------|
| 19–23 | Basics, Repeater, Intruder, Other Modules, Extensions |

### Web Application Vulnerabilities I & II
| # | Room |
|---|------|
| 24–28 | SQL Injection, CSRF, XSS, SSRF, IDOR |
| 29–33 | Session Management, Broken Authentication, File Inclusion, Command Injection, API Pentesting |

### Vulnerability Knowledge & OWASP Top 10
| # | Room |
|---|------|
| 34–39 | Vulnerability Databases, NoScope, n8n CVE, AD BadSuccessor, Fragnesia, Nginx Rift |
| 40 | OWASP Top 10 (2025) |

### Password Attacks
| # | Room |
|---|------|
| 41–43 | Phishing Basics, Wordlists, Password Cracking |

### Metasploit & Exploitation
| # | Room |
|---|------|
| 44–49 | Metasploit Basics, Scanning & Exploitation, Post-Exploitation, Payload Generation, Shells & Listeners |

### Privilege Escalation
| # | Room |
|---|------|
| 50–54 | Host-Server Config Reviews, Linux Priv Esc (Enumeration, Basics, Automation), Windows Privilege Escalation |

### Active Directory Security Testing
| Room |
|------|
| AD Basics, Authentication, Breaching, Enumeration, Authenticated Enumeration, Credential Harvesting, Lateral Movement |
| Challenges: Proxy, Forward |

### Specialized Domains
| Room |
|------|
| Wireless Security, Mobile Application Security, Cloud Security Fundamentals, LLM Pentesting, Blue Team Perspective, DevSecOps Basics |

### Python Scripting for Pentesting
| Room |
|------|
| Simple Demo, Core Concepts, Building Scripts, Pentesting Scripts |

### Pentesting Methodologies & Reporting
| Room |
|------|
| Threat Modeling, Planning & Scoping, Writing Pentest Reports, Re-Testing |

### Jr Pentester Challenges
| Challenge | Description |
|---|---|
| [Domino](./TryHackMe/Jr-Penetration-Tester/Domino-Challenge.md) | Chained vulnerabilities, cascading attack path |
| [Recruit](./TryHackMe/Jr-Penetration-Tester/Recruit-Challenge.md) | Entry-level end-to-end engagement |
| [Support](./TryHackMe/Jr-Penetration-Tester/Support-Challenge.md) | Full engagement simulation |
| [Silent Monitor](./TryHackMe/Jr-Penetration-Tester/Silent-Monitor-Writeup/) | Internal service enumeration → web exploitation → pivot → crack to root |
| [Operation Coldstart](./TryHackMe/Jr-Penetration-Tester/Operation-Coldstart-Writeup/) | Waking and compromising a staging server |
| [Interceptor](./TryHackMe/Jr-Penetration-Tester/Interceptor-Writeup/) | Traffic interception and modification to pwn the machine |

*(Rooms without writeups yet are being backfilled from raw notes — this repo is a living document, updated as I go.)*

---
