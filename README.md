# Firebase Security Scanner v3.0

Comprehensive security testing tool for Firebase projects. Designed for authorized bug bounty hunters and penetration testers.

## Features (18 Security Tests)

| # | Test | Type | Severity |
|---|------|------|----------|
| 1 | Open Registration | AUTH | INFO |
| 2 | Email Enumeration | AUTH | LOW |
| 3 | Weak Password Policy | AUTH | LOW |
| 4 | Password Reset Abuse | AUTH | LOW |
| 5 | JWT Token Analysis | AUTH | INFO |
| 6 | Firestore READ | DATA_LEAK | HIGH |
| 7 | Firestore WRITE | WRITE | CRITICAL |
| 8 | IDOR/BOLA | IDOR | CRITICAL |
| 9 | DELETE Access | DELETE | CRITICAL |
| 10 | Config Hijack | CONFIG | CRITICAL |
| 11 | Privilege Escalation | PRIVESC | HIGH |
| 12 | Storage Bucket + Upload | STORAGE | HIGH/CRITICAL |
| 13 | Realtime Database | RTDB | CRITICAL |
| 14 | Sensitive Files | FILES | MEDIUM |
| 15 | Source Maps | SOURCEMAP | MEDIUM |
| 16 | CORS Misconfiguration | CORS | MEDIUM/HIGH |
| 17 | Security Headers (CSP) | HEADERS | MEDIUM |
| 18 | Remote Config | REMOTECONFIG | HIGH |

## Installation

```bash
cd firebase_tests
pip install -r requirements.txt
```

## Usage

```bash
python3 firebase_scanner.py
```

### Input

```
API Key: AIzaSy...
Project ID: project-12345
Storage Bucket: (Enter to auto-detect)
App URL: https://app.example.com (optional)
```

### Finding Firebase Config

Look in target's source code:

```javascript
const firebaseConfig = {
  apiKey: "AIzaSy...",           // Required
  projectId: "project-12345",    // Required
  storageBucket: "...",          // Optional
  authDomain: "...",             // Optional
};
```

Or check:
- View Source (`Ctrl+U`)
- DevTools > Sources > main.js
- `/__/firebase/init.json` endpoint

## Output

1. **Color-coded findings** by severity
2. **Ready-to-use curl commands** for PoC
3. **Bug bounty report template**
4. **Remediation guidance**

## Example Output

```
╔══════════════════════════════════════════════════════════════════════╗
║                    Firebase Security Scanner v3.0                     ║
╚══════════════════════════════════════════════════════════════════════╝

[1/18] Testing Open Registration...
    [VULN] Open registration ENABLED!

[6/18] Testing Firestore READ Access (Data Leak)...
    [VULN] 'users' READABLE - 47 documents
    [VULN] 'app_config' READABLE - 1 documents

[8/18] Testing IDOR/BOLA (Access Other Users)...
    [CRITICAL] IDOR! Can access 46 OTHER users!
    [CRITICAL] Can MODIFY other users!

===========================================================================
                           SCAN RESULTS
===========================================================================

CRITICAL: 4  HIGH: 2  MEDIUM: 1  LOW: 2

[CRITICAL] IDOR: IDOR/BOLA - Access Other Users
       Can access 46 other users' data
       Impact: Account takeover, mass data breach
```

## Vulnerability Categories

### Critical
- **IDOR/BOLA** - Access other users' data
- **Firestore Write** - Modify any document
- **Delete Access** - Destroy data
- **Config Hijack** - Redirect API traffic
- **RTDB Exposed** - Full database public
- **Storage Upload** - Upload malicious files

### High
- **Data Leak** - Read sensitive collections
- **Privilege Escalation** - Self-promote to admin
- **Storage Exposure** - List/download files
- **CORS Reflection** - Origin bypass

### Medium
- **Missing CSP** - XSS risk
- **Source Maps** - Code exposure
- **Sensitive Files** - .env, .git exposed

### Low
- **Email Enumeration** - Discover valid emails
- **Weak Passwords** - No complexity requirements

## Legal Disclaimer

**For authorized testing only.**

- Only test applications you have explicit permission to test
- Follow responsible disclosure practices
- Comply with bug bounty program rules
- Do not use for malicious purposes

## Bug Bounty Tips

### What Makes a Good Report

1. **Prove impact** - Show real data, not just access
2. **Include PII** - Redacted emails/phones prove severity
3. **Clear reproduction** - Token generation + curl commands
4. **Screenshots** - Response bodies, data samples

### Common Mistakes

- Reporting API keys alone (they're meant to be public)
- Not demonstrating real impact
- Missing reproduction steps
- Submitting duplicates (same root cause)

### VRT Categories

- Broken Access Control > IDOR
- Server Misconfiguration > Insecure Firebase
- Server Misconfiguration > Missing CSP

## Files

```
firebase_tests/
├── firebase_scanner.py   # Main scanner (18 tests)
├── requirements.txt      # Dependencies
└── README.md             # This file
```

## Changelog

### v3.0
- Added 18 comprehensive security tests
- JWT token analysis
- Email enumeration
- Password policy testing
- Source map detection
- CORS testing
- Storage upload testing
- Remote config testing
- Sensitive file discovery
- Color-coded output
- Auto-generated report template

## Author

Security Researcher - Bug Bounty Edition

x.com/sagarbanwa

## License

MIT - Use responsibly.
