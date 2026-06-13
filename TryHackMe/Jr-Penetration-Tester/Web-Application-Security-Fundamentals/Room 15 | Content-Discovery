# Content Discovery

## What is the room about
content discovery of the target with finding content that wasn't meant to publicly accessible.

## Tools used
- curl
- Gobuster
- Wappalyzer
- Google Dorking
- Wayback Machine

## What I learned
### Manual Approach
- How robots.txt may list sensitive directories to prevent them from appearing in search result
- Used sitemap.xml to discover pages beyond normal site
- How to explore web server responds to reveal technical details like web server software and framework
- Identified the framework from favicon, headers, or by inspecting page source

### OSINT Approach
- How to use search engines and tools for discovering info
- Combined Google's advanced search operators to filter results
- Used Wappalyzer extension to detect framework
- Explored repositories on GitHub & S3 buckets to reveal sensitive data 

### Automated Discovery
- How to enumerate using Gobuster for dir, dns, and vhost
  - Gobuster dir mode — brute forces directories
  - Gobuster dns mode — brute forces subdomains  
  - Gobuster vhost mode — finds virtual hosts via Host header
- Explored SecLists Wordlist

## Key Commands
### View HTTP headers
curl http://example.thm -v

### Directory enumeration
gobuster dir -u "http://10.113.168.70" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

### DNS subdomain enumeration
gobuster dns -d acmeitsupport.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

### Virtual host enumeration
gobuster vhost -u "http://10.113.168.70" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

## Key Takeaway
Always start content discovery manually before running 
automated tools. robots.txt and sitemap.xml alone can 
reveal sensitive paths without making a single scan.

## Flags
- Flag 1 (robot.txt): THM{/staff-portal}
- Flag 2 (sitemap.xml): THM{/s3cr3t-area}
- Flag 3 (X-FLAG header): THM{HEADER_FLAG}
- Flag 4 (framework): THM{CHANGE_DEFAULT_CREDENTIALS}
- Flag 5 (Google dork): THM{site:}
- Flag 6 (tool): THM{Wappalyzer}
- Flag 7 (Wayback Machine addr): THM{https://web.archive.org/}
- Flag 8 (Amazon S3): THM{.s3.amazonaws.com}
- Flag 9 (/mo dir): THM{/monthly}
- Flag 10 (log file): THM{/development.log}
- Flag 11 (dns flag): THM{-d}
- Flag 12 (hosts count): THM{3}
