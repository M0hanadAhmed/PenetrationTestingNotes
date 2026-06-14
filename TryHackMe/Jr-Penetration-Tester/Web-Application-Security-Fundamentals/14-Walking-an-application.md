#  Walking an Application

## What this room is about
Manual web application assessing using built-in browser tools.

## Tools used
- Browser Developer Tools (Inspector, Debugger, Network, Storage)
- Page Source (view-source:)

## What I learned

### 1. Page Source
- How to view hidden comments and links in HTML
- Understood the structure of webpages and their contents
- How to find exposed directories with sensitive files
- How to identify frameworks and versions from source code

### 2. Inspector
- How to modify CSS in real time to bypass paywalls
- Changed the page's content and style (display:block to display:none to reveal hidden content)

### 3. Debugger
- How to dig into the JavaScript code (in Chrome called Sources)
- How to deal with the interactive elements of the webpage
- How to use breakpoints to pause JS execution
- Found a red flash element being removed by flash.min.js

### 4. Network
- How to intercept AJAX from Submissions (a method for sending and receiving network data in the background without interfering with the current page).
- Examined the request and interacted with its details (headers, cookie details, and HTML responses)

### 5. Storage Tab
- How to reveal sensitive information
- Understood the options inside it (Local Storage, Session, Cookies, Cache)
- Cookies are most important for pentesters
- HTTPOnly flag - prevents XSS from stealing cookies
- Secure flag - cookie only sent over HTTPS
- SameSite - protects against CSRF

## Key Takeaway
Before using any hacking tool, always manually explore the application using browser dev tools first. Hidden comments, exposed directories, and framework versions can all be found without running a single scan.

## Flags
- Flag 1 (Endpoint for creating tickets): THM{/customers/ticket/new}
- Flag 2 (Flag from HTML comment): THM{HTML_COMMENTS_ARE_DANGEROUS}
- Flag 3 (Page source hidden link): THM{NOT_A_SECRET_ANYMORE}
- Flag 4 (Directory listing): THM{INVALID_DIRECTORY_PERMISSIONS}
- Flag 5 (Framework flag): THM{KEEP_YOUR_SOFTWARE_UPDATED}
- Flag 6 (Inspector flag): THM{NOT_SO_HIDDEN}
- Flag 7 (debugger flag): THM{CATCH_ME_IF_YOU_CAN}
- Flag 8 (Network flag): THM{GOT_AJAX_FLAG}
- Flag 9 (Storage flag): false
