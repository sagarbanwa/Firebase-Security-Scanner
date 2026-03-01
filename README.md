# Firebase Security Scanner

A comprehensive security testing tool for Firebase projects. Designed for authorized bug bounty hunters and penetration testers.

## Features

| Test | Description | Severity |
|------|-------------|----------|
| Open Registration | Check if anyone can create accounts | INFO |
| Firestore READ | Enumerate accessible collections & PII | HIGH |
| Firestore WRITE | Test unauthorized data modification | CRITICAL |
| IDOR/BOLA | Access other users' documents | CRITICAL |
| DELETE Access | Test data destruction capabilities | CRITICAL |
| Config Hijack | Modify app configuration (API redirect) | CRITICAL |
| Privilege Escalation | Self-promote to admin | HIGH |
| Storage Bucket | List/download files | HIGH |
| Realtime Database | Check for public RTDB access | CRITICAL |
| CSP Headers | Missing security headers | MEDIUM |
| API Key Restrictions | Check for unrestricted API key | LOW |
| Cloud Functions | Discover callable endpoints | INFO |

## Installation

```bash
# Clone or download
cd firebase_tests

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python3 firebase_scanner.py
```

### Input Required

You'll need the Firebase config from the target application (usually found in source code):

```
API Key: AIzaSy...
Project ID: project-name-12345
Storage Bucket: (optional - auto-detected)
App URL: https://app.example.com (optional - for CSP test)
```

### Finding Firebase Config

Look in the target's source code for:

```javascript
const firebaseConfig = {
  apiKey: "AIzaSy...",
  authDomain: "project.firebaseapp.com",
  projectId: "project-12345",
  storageBucket: "project.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123:web:abc123"
};
```

## Output

The scanner provides:

1. **Color-coded findings** - CRITICAL (red), HIGH (yellow), MEDIUM (blue)
2. **Ready-to-use curl commands** - Copy-paste PoC for each vulnerability
3. **Bug bounty report template** - Pre-formatted report for submission
4. **Remediation guidance** - Firestore security rules examples

## Example Output

```
[CRITICAL] IDOR: IDOR/BOLA - Access Other Users
           Can read/modify 15 other users' documents without authorization
           Impact: Full account takeover, mass data breach, privacy violation

[HIGH] DATA_LEAK: Firestore Data Exposure
       3 collections readable with 47 total documents. PII detected: ['email', 'phone']
       Impact: Mass data exposure, potential GDPR violation
```

## Supported Vulnerability Categories (VRT)

- **Broken Access Control (BAC)** > Insecure Direct Object References (IDOR)
- **Server Security Misconfiguration** > Insecure Firebase Configuration
- **Server Security Misconfiguration** > Missing Content Security Policy

## Legal Disclaimer

This tool is intended for **authorized security testing only**.

- Only test applications you have permission to test
- Follow responsible disclosure practices
- Comply with bug bounty program rules
- Do not use for malicious purposes

The author is not responsible for misuse of this tool.

## Bug Bounty Tips

### What Makes a Good Firebase Report

1. **Prove real impact** - Show actual data, not just "I can access X"
2. **Include PII if found** - Redacted emails, phone numbers prove severity
3. **Provide clear reproduction steps** - Token generation, curl commands
4. **Document everything** - Screenshots, response bodies

### Common Mistakes

- Reporting exposed API keys alone (they're meant to be public)
- Not demonstrating actual impact
- Missing reproduction steps
- Submitting duplicates (different symptoms, same root cause)

### Report Template

```markdown
## Title
[Vulnerability Type] in Firebase Project [project-id]

## Severity
[CRITICAL/HIGH/MEDIUM]

## Summary
Brief description of the vulnerability and its impact.

## Steps to Reproduce
1. Register account via Firebase Auth API
2. Use token to access Firestore REST API
3. [Specific curl commands]

## Impact
- What an attacker can do
- What data is exposed
- Business impact

## Remediation
Firestore security rules fix.
```

## Author

Security Researcher - Bug Bounty Edition

## License

MIT License - Use responsibly.
