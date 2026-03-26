import re
import urllib

import chromadb
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from openai import OpenAI
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
import hashlib
import os
from drain3.masking import MaskingInstruction

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------------------------
# Attack Taxonomy με Severity
# -------------------------

ATTACK_TAXONOMY = {
    # Reconnaissance
    "vulnerability_scanner": {"category": "recon", "severity": 7, "mitre": "T1595"},
    "directory_enumeration": {"category": "recon", "severity": 5, "mitre": "T1083"},
    "web_fingerprinting": {"category": "recon", "severity": 4, "mitre": "T1592"},
    "sensitive_file_probe": {"category": "recon", "severity": 6, "mitre": "T1083"},
    "backup_file_probe": {"category": "recon", "severity": 7, "mitre": "T1083"},
    "config_file_probe": {"category": "recon", "severity": 8, "mitre": "T1083"},

    # Injection Attacks
    "sql_injection": {"category": "injection", "severity": 9, "mitre": "T1190"},
    "sql_injection_union": {"category": "injection", "severity": 9, "mitre": "T1190"},
    "sql_injection_blind": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "sql_injection_time": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "sql_injection_error": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "xss_reflected": {"category": "injection", "severity": 7, "mitre": "T1059.007"},
    "xss_stored": {"category": "injection", "severity": 8, "mitre": "T1059.007"},
    "command_injection": {"category": "injection", "severity": 10, "mitre": "T1059"},
    "code_injection": {"category": "injection", "severity": 10, "mitre": "T1059"},
    "ldap_injection": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "xpath_injection": {"category": "injection", "severity": 7, "mitre": "T1190"},
    "ssi_injection": {"category": "injection", "severity": 7, "mitre": "T1190"},

    # Path Traversal & LFI/RFI
    "path_traversal": {"category": "file_access", "severity": 8, "mitre": "T1083"},
    "lfi": {"category": "file_access", "severity": 9, "mitre": "T1083"},
    "rfi": {"category": "file_access", "severity": 10, "mitre": "T1105"},

    # Authentication Attacks
    "brute_force_ssh": {"category": "credential", "severity": 7, "mitre": "T1110"},
    "brute_force_web": {"category": "credential", "severity": 7, "mitre": "T1110"},
    "LOGIN_PATTERNS": {"category": "credential", "severity": 4, "mitre": "T1110"},
    "credential_stuffing": {"category": "credential", "severity": 8, "mitre": "T1110.004"},
    "password_spray": {"category": "credential", "severity": 7, "mitre": "T1110.003"},
    "default_credentials": {"category": "credential", "severity": 6, "mitre": "T1078.001"},

    # Web Application Attacks
    "admin_panel_probe": {"category": "webapp", "severity": 5, "mitre": "T1190"},
    "cms_exploit": {"category": "webapp", "severity": 8, "mitre": "T1190"},
    "webshell_upload": {"category": "webapp", "severity": 10, "mitre": "T1505.003"},
    "file_upload_bypass": {"category": "webapp", "severity": 9, "mitre": "T1190"},

    # Protocol/Server Attacks
    "http_method_tampering": {"category": "protocol", "severity": 5, "mitre": "T1190"},
    "http_smuggling": {"category": "protocol", "severity": 8, "mitre": "T1190"},
    "header_injection": {"category": "protocol", "severity": 6, "mitre": "T1190"},

    # Infrastructure
    "cisco_ios_probe": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},
    "router_exploit": {"category": "infrastructure", "severity": 9, "mitre": "T1190"},
    "iis_exploit": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},
    "apache_exploit": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},
    "tomcat_exploit": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},

    # Cisco ASA Firewall
    "asa_port_scan":        {"category": "recon",      "severity": 7, "mitre": "T1046"},
    "asa_fw_bypass":        {"category": "evasion",    "severity": 8, "mitre": "T1562"},
    "asa_vpn_bruteforce":   {"category": "credential", "severity": 8, "mitre": "T1110"},
    "asa_connection_flood": {"category": "dos",        "severity": 9, "mitre": "T1498"},
    "asa_denied":           {"category": "firewall",   "severity": 6, "mitre": "T1190"},

    # DoS/DDoS
    "ddos": {"category": "dos", "severity": 9, "mitre": "T1498"},

    # Benign
    "normal": {"category": "benign", "severity": 0, "mitre": None},
    "monitoring": {"category": "benign", "severity": 1, "mitre": None},
}


# -------------------------
# Detection Patterns
# -------------------------

class AttackDetector:
    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self):
        return {
            # SQL Injection - Granular
            "sql_injection_union": [
                # Καλύπτει union select με κενά, +, ή %20
                re.compile(r"union(\s+|%20|\+)(all(\s+|%20|\+))?select", re.I),
            ],
            "sql_injection_blind": [
                # Πιάνει το or 1=1, or 1%3D1, ή or 1 = 1
                re.compile(r"(and|or)(\s+|%20|\+)\d+(\s+|%20|\+)?(=|%3D)(\s+|%20|\+)?\d+", re.I),
                re.compile(r"'\s*(and|or)\s*'", re.I),
                # Πιάνει το -- (comment) ακόμα και αν είναι encoded ως %2D%2D
                re.compile(r"(--|%2d%2d|#|%23)", re.I),
            ],
            "sql_injection_time": [
                re.compile(r"sleep\s*\(|waitfor(\s+|%20|\+)delay|benchmark\s*\(|pg_sleep", re.I),
            ],
            "sql_injection_error": [
                re.compile(r"extractvalue|updatexml|floor\s*\(\s*rand|exp\s*\(\s*~", re.I),
            ],
            "sql_injection": [
                # Πολύ σημαντικό: Πιάνει την πρόσβαση σε metadata
                re.compile(r"information_schema|table_name|column_name", re.I),
                re.compile(r"(drop|insert|delete|update)(\s+|%20|\+)(table|into|from|set)", re.I),
                re.compile(r"(load_file|into(\s+|%20|\+)outfile|group_concat|concat)\s*\(", re.I),
                re.compile(r"@@version|char\s*\(\d+|0x[0-9a-f]{6,}", re.I),
                # Πιάνει semicolons μόνο με SQL context (Fix 1: αποφυγή false positives σε path traversal)
                re.compile(r"(select|insert|update|delete|drop|union|where)\s*;", re.I),
                re.compile(r";\s*(select|insert|update|delete|drop|union)", re.I),
            ],

            # XSS
            "xss_reflected": [
                re.compile(r"<script[^>]*>", re.I),
                re.compile(r"</script>", re.I),
                re.compile(r"javascript\s*:", re.I),
                re.compile(r"on(error|load|click|mouse|focus)\s*=", re.I),
                re.compile(r"<img[^>]+onerror", re.I),
                re.compile(r"<svg[^>]+onload", re.I),
                re.compile(r"<iframe", re.I),
                re.compile(r"%3Cscript", re.I),
                re.compile(r"alert\s*\(", re.I),
                re.compile(r"document\.cookie", re.I),
                re.compile(r"document\.domain", re.I),
            ],

            # Command Injection
            "command_injection": [
                re.compile(r";\s*(ls|cat|pwd|id|whoami|uname)", re.I),
                re.compile(r"\|\s*(ls|cat|pwd|id|whoami)", re.I),
                re.compile(r"`[^`]+`"),
                re.compile(r"\$\([^)]+\)"),
                re.compile(r"system\s*\(", re.I),
                re.compile(r"exec\s*\(", re.I),
                re.compile(r"passthru\s*\(", re.I),
                re.compile(r"shell_exec", re.I),
                re.compile(r"popen\s*\(", re.I),
                re.compile(r"proc_open", re.I),
                re.compile(r"/bin/(bash|sh|zsh)", re.I),
                re.compile(r"cmd\.exe", re.I),
                re.compile(r"powershell", re.I),
            ],

            # Path Traversal / LFI
            "path_traversal": [
                re.compile(r"\.\./"),
                re.compile(r"\.\.\\"),
                re.compile(r"%2e%2e[/%5c]", re.I),
                re.compile(r"\.\.%2f", re.I),
                re.compile(r"\.\.%5c", re.I),
                re.compile(r"%252e%252e", re.I),
            ],
            "lfi": [
                re.compile(r"/etc/passwd"),
                re.compile(r"/etc/shadow"),
                re.compile(r"/etc/hosts"),
                re.compile(r"/proc/self"),
                re.compile(r"/var/log"),
                re.compile(r"c:\\\\windows", re.I),
                re.compile(r"c:\\\\boot\.ini", re.I),
                re.compile(r"boot\.ini", re.I),
                re.compile(r"win\.ini", re.I),
            ],
            "rfi": [
                re.compile(r"=\s*https?://", re.I),
                re.compile(r"=\s*ftp://", re.I),
                re.compile(r"=\s*php://", re.I),
                re.compile(r"=\s*data://", re.I),
                re.compile(r"=\s*expect://", re.I),
                re.compile(r"=\s*file://", re.I),
                re.compile(r"rfiinc\.txt", re.I),
            ],

            # Vulnerability Scanners
            "vulnerability_scanner": [
                re.compile(r"nikto", re.I),
                re.compile(r"nessus", re.I),
                re.compile(r"acunetix", re.I),
                re.compile(r"sqlmap", re.I),
                re.compile(r"wpscan", re.I),
                re.compile(r"openvas", re.I),
                re.compile(r"nmap", re.I),
                re.compile(r"masscan", re.I),
                re.compile(r"burpsuite", re.I),
                re.compile(r"zap/", re.I),
                re.compile(r"dirbuster", re.I),
                re.compile(r"gobuster", re.I),
                re.compile(r"ffuf", re.I),
                re.compile(r"wfuzz", re.I),
            ],

            # Sensitive File Probing
            "config_file_probe": [
                re.compile(r"\.env$", re.I),
                re.compile(r"\.git/config", re.I),
                re.compile(r"wp-config\.php", re.I),
                re.compile(r"config\.php", re.I),
                re.compile(r"settings\.php", re.I),
                re.compile(r"database\.yml", re.I),
                re.compile(r"\.htaccess", re.I),
                re.compile(r"\.htpasswd", re.I),
                re.compile(r"web\.config", re.I),
                re.compile(r"applicationhost\.config", re.I),
                re.compile(r"php\.ini", re.I),
                re.compile(r"my\.cnf", re.I),
            ],
            "backup_file_probe": [
                re.compile(r"\.(bak|backup|old|orig|copy|tmp|temp)$", re.I),
                re.compile(r"\.(sql|dump|gz|tar|zip|rar|7z)$", re.I),
                re.compile(r"~$"),
                re.compile(r"\.swp$"),
                re.compile(r"#.*#$"),
                re.compile(r"\.(war|ear|jar)$", re.I),
            ],
            "sensitive_file_probe": [
                re.compile(r"\.(pem|cer|crt|key|jks|p12|pfx)$", re.I),
                re.compile(r"id_rsa"),
                re.compile(r"\.ssh/"),
                re.compile(r"authorized_keys"),
                re.compile(r"\.aws/credentials", re.I),
                re.compile(r"\.docker/config", re.I),
            ],

            # Admin Panel Probing
            "admin_panel_probe": [
                re.compile(r"/admin[^a-z]", re.I),
                re.compile(r"/administrator", re.I),
                re.compile(r"/manager/", re.I),
                re.compile(r"/phpmyadmin", re.I),
                re.compile(r"/adminer", re.I),
                re.compile(r"/wp-admin", re.I),
                re.compile(r"/wp-login", re.I),
                re.compile(r"/controlpanel", re.I),
                re.compile(r"/cpanel", re.I),
                re.compile(r"/webadmin", re.I),
                re.compile(r"/siteadmin", re.I),
            ],

            # CMS Exploits
            "cms_exploit": [
                re.compile(r"xmlrpc\.php", re.I),
                re.compile(r"wp-content/plugins", re.I),
                re.compile(r"wp-includes", re.I),
                re.compile(r"components/com_", re.I),
                re.compile(r"index\.php\?option=com_", re.I),
                re.compile(r"modules\.php\?name=", re.I),
                re.compile(r"postnuke", re.I),
                re.compile(r"phpnuke", re.I),
                re.compile(r"phpbb", re.I),
                re.compile(r"joomla", re.I),
                re.compile(r"drupal", re.I),
            ],

            # Authentication Attacks
            "brute_force_ssh": [
                re.compile(r"failed\s+password\s+for", re.I),
                re.compile(r"authentication\s+failure", re.I),
                re.compile(r"invalid\s+user", re.I),
                re.compile(r"sshd\[.*\]:\s+failed", re.I),
            ],
            "brute_force_web": [
                re.compile(r"login\s+failed", re.I),
                re.compile(r"auth.*failed", re.I),
                re.compile(r"access\s+denied", re.I),
                re.compile(r"401\s", re.I),
            ],
            "LOGIN_PATTERNS": [
                re.compile(r"/login", re.I),
                re.compile(r"/wp-login\.php", re.I),
                re.compile(r"/admin/login", re.I),
                re.compile(r"/signin", re.I),
                re.compile(r"/user/login", re.I),
            ],

            # Infrastructure Attacks
            "cisco_ios_probe": [
                re.compile(r"/level/\d+/exec", re.I),
                re.compile(r"/exec/show", re.I),
                re.compile(r"show\s+config", re.I),
                re.compile(r"show\s+running", re.I),
                re.compile(r"show\s+version", re.I),
            ],
            "iis_exploit": [
                re.compile(r"\.ida$", re.I),
                re.compile(r"\.idq$", re.I),
                re.compile(r"\.printer$", re.I),
                re.compile(r"\.htr$", re.I),
                re.compile(r"_vti_bin", re.I),
                re.compile(r"_vti_pvt", re.I),
                re.compile(r"msadc/", re.I),
            ],
            "tomcat_exploit": [
                re.compile(r"/manager/html", re.I),
                re.compile(r"/host-manager", re.I),
                re.compile(r"/jk-manager", re.I),
                re.compile(r"/jk-status", re.I),
                re.compile(r"\.jsp%00", re.I),
                re.compile(r"/invoker/", re.I),
            ],
            "apache_exploit": [
                re.compile(r"/server-status", re.I),
                re.compile(r"/server-info", re.I),
                re.compile(r"\.htaccess", re.I),
                re.compile(r"mod_status", re.I),
            ],

            # SSI Injection
            "ssi_injection": [
                re.compile(r"<!--\s*#\s*(exec|include|echo)", re.I),
                re.compile(r"\.shtml", re.I),
                re.compile(r"\.stm", re.I),
            ],

            # HTTP Method Tampering
            "http_method_tampering": [
                re.compile(r'"(TRACE|TRACK|DEBUG|OPTIONS|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|PATCH)\s+/',
                           re.I),
            ],

            # Webshell Indicators
            "webshell_upload": [
                re.compile(r"c99\.php", re.I),
                re.compile(r"r57\.php", re.I),
                re.compile(r"shell\.php", re.I),
                re.compile(r"cmd\.php", re.I),
                re.compile(r"backdoor", re.I),
                re.compile(r"webshell", re.I),
                re.compile(r"FilesMan", re.I),
            ],

            # Directory Enumeration
            "directory_enumeration": [
                re.compile(r"/[a-zA-Z0-9]{6,10}\.(php|asp|aspx|jsp|txt|html?|xml|json|sql|bak)$"),
            ],

            # Web Fingerprinting
            "web_fingerprinting": [
                re.compile(r"robots\.txt", re.I),
                re.compile(r"sitemap\.xml", re.I),
                re.compile(r"crossdomain\.xml", re.I),
                re.compile(r"security\.txt", re.I),
                re.compile(r"\.well-known", re.I),
                re.compile(r"phpinfo\.php", re.I),
                re.compile(r"info\.php", re.I),
                re.compile(r"test\.php", re.I),
                re.compile(r"\?=PHP[A-Z0-9]+-", re.I),
            ],

            # -----------------------------------------------------------------
            # Cisco ASA Firewall Patterns
            # -----------------------------------------------------------------
            "asa_port_scan": [
                re.compile(r"%ASA-\d-733100", re.I),
                re.compile(r"%ASA-\d-733101", re.I),
                re.compile(r"port\s+scan", re.I),
                re.compile(r"scanning\s+detected", re.I),
            ],
            "asa_fw_bypass": [
                re.compile(r"%ASA-\d-106100", re.I),
                re.compile(r"%ASA-\d-710003", re.I),
                re.compile(r"%ASA-\d-710005", re.I),
                re.compile(r"access-list\s+\S+\s+denied", re.I),
                re.compile(r"deny\s+\w+\s+src\s+outside", re.I),
            ],
            "asa_vpn_bruteforce": [
                re.compile(r"%ASA-\d-113005", re.I),
                re.compile(r"%ASA-\d-113006", re.I),
                re.compile(r"%ASA-\d-113015", re.I),
                re.compile(r"%ASA-\d-113021", re.I),
                re.compile(r"AAA\s+user\s+authentication\s+Rejected", re.I),
                re.compile(r"locked\s+out\s+exceeding\s+maximum\s+failed", re.I),
                re.compile(r"Invalid\s+password", re.I),
            ],
            "asa_connection_flood": [
                re.compile(r"%ASA-\d-419001", re.I),
                re.compile(r"%ASA-\d-419002", re.I),
                re.compile(r"half-open\s+TCP\s+connections", re.I),
                re.compile(r"embryonic\s+conn\s+limit\s+exceeded", re.I),
                re.compile(r"SYN\s+flood", re.I),
                re.compile(r"connection\s+flood\s+detected", re.I),
            ],
            "asa_denied": [
                re.compile(r"%ASA-\d-106023", re.I),
                re.compile(r"%ASA-\d-106001", re.I),
                re.compile(r"%ASA-\d-106006", re.I),
                re.compile(r"%ASA-\d-106007", re.I),
                re.compile(r"Inbound\s+\w+\s+connection\s+denied", re.I),
            ],
        }

    def detect(self, log):
        """Detect all attack types in a log entry"""
        attacks = []

        # 1. ΚΑΘΑΡΙΣΜΟΣ: Μετατρέπουμε το log σε "ανθρώπινη" μορφή
        # π.χ. το %20 γίνεται κενό, το %27 γίνεται ' κτλ.
        decoded_log = urllib.parse.unquote(log)

        # 2. ΑΝΑΛΥΣΗ: Τρέχουμε τα patterns πάνω στο DECODED log
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                # Χρησιμοποιούμε το decoded_log αντί για το σκέτο log
                if pattern.search(decoded_log):
                    attacks.append(attack_type)
                    break

                    # Το υπόλοιπο κομμάτι παραμένει ως έχει
        attacks = self._deduplicate_attacks(attacks)

        if not attacks:
            if " 404 " in log:  # Εδώ το log είναι οκ, γιατί το " 404 " δεν είναι encoded
                attacks.append("directory_enumeration")
            else:
                attacks.append("normal")

        return attacks

    def _deduplicate_attacks(self, attacks):
        """Remove generic attacks if specific ones are present"""
        specific_map = {
            "sql_injection": ["sql_injection_union", "sql_injection_blind",
                              "sql_injection_time", "sql_injection_error"],
        }

        # Fix 2: Αν ανιχνευτεί path traversal/lfi/rfi, αφαίρεσε generic sql_injection
        # που ενεργοποιήθηκε λάθος από semicolon
        file_access = {"path_traversal", "lfi", "rfi"}
        if any(a in attacks for a in file_access):
            attacks = [a for a in attacks if a not in
                       ("sql_injection", "sql_injection_blind")]

        # Fix 3: Αν ανιχνευτεί injection, το LOGIN_PATTERNS είναι noise
        # Αποφεύγουμε να εκπαιδεύσουμε το μοντέλο με λανθασμένες ετικέτες
        injection_types = {
            "sql_injection", "sql_injection_blind", "sql_injection_union",
            "sql_injection_time", "sql_injection_error",
            "command_injection", "code_injection"
        }
        if any(a in attacks for a in injection_types):
            attacks = [a for a in attacks if a != "LOGIN_PATTERNS"]

        # Fix 4: Αν υπάρχει LOGIN_PATTERNS ή brute_force, το /admin/login
        # δεν είναι admin probe — είναι credential attack
        cred_types = {"LOGIN_PATTERNS", "brute_force_web", "brute_force_ssh"}
        if any(a in attacks for a in cred_types):
            attacks = [a for a in attacks if a != "admin_panel_probe"]

        # Fix 5: %ASA-4-733100 ανήκει και στα δύο patterns
        # asa_connection_flood είναι πιο specific από asa_port_scan
        if "asa_connection_flood" in attacks:
            attacks = [a for a in attacks if a != "asa_port_scan"]

        # Fix 6: %ASA-4-106023 ανήκει και στα δύο patterns
        # asa_fw_bypass είναι πιο specific από asa_denied
        if "asa_fw_bypass" in attacks:
            attacks = [a for a in attacks if a != "asa_denied"]

        result = attacks.copy()
        for generic, specifics in specific_map.items():
            if generic in result:
                if any(s in result for s in specifics):
                    result.remove(generic)

        return list(set(result))

    def get_severity(self, attacks):
        """Calculate max severity from attack list"""
        max_severity = 0
        for attack in attacks:
            if attack in ATTACK_TAXONOMY:
                max_severity = max(max_severity, ATTACK_TAXONOMY[attack]["severity"])
        return max_severity

    def get_mitre_tactics(self, attacks):
        """Get MITRE ATT&CK tactics"""
        tactics = set()
        for attack in attacks:
            if attack in ATTACK_TAXONOMY and ATTACK_TAXONOMY[attack]["mitre"]:
                tactics.add(ATTACK_TAXONOMY[attack]["mitre"])
        return list(tactics)


# -------------------------
# Log Normalizer
# -------------------------

class LogNormalizer:
    def __init__(self):
        self.ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.timestamp_patterns = [
            re.compile(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]'),
            re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'),
            re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),
        ]
        self.hex_pattern = re.compile(r'0x[0-9a-fA-F]+')
        self.random_string = re.compile(r'/[a-zA-Z0-9]{8,12}\.')
        self.port_pattern = re.compile(r'port\s+\d+')
        self.pid_pattern = re.compile(r'\[\d+\]')
        self.session_pattern = re.compile(r'session\s+\d+', re.I)
        self.size_pattern = re.compile(r'"\s+\d{3}\s+\d+')

    def normalize(self, log):
        """Normalize log for better template extraction"""
        normalized = log

        # Replace IPs with placeholder
        normalized = self.ip_pattern.sub('<IP>', normalized)

        # Replace timestamps
        for pattern in self.timestamp_patterns:
            normalized = pattern.sub('<TIMESTAMP>', normalized)

        # Replace hex values
        normalized = self.hex_pattern.sub('<HEX>', normalized)

        # Replace random filename patterns (scanner signatures)
        normalized = self.random_string.sub('/<RANDOM_FILE>.', normalized)

        # Replace ports
        normalized = self.port_pattern.sub('port <PORT>', normalized)

        # Replace PIDs
        normalized = self.pid_pattern.sub('[<PID>]', normalized)

        # Replace session IDs
        normalized = self.session_pattern.sub('session <SESSION>', normalized)

        return normalized

    def extract_metadata(self, log):
        """Extract useful metadata from log — υποστηρίζει Apache και Cisco ASA format"""
        metadata = {}

        # --- Cisco ASA format detection ---
        is_cisco = bool(re.search(r'%ASA-\d-\d+', log, re.I))

        if is_cisco:
            cisco_ip = re.search(
                r'(?:src\s+\w+:|from\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log, re.I
            )
            metadata['source_ip'] = cisco_ip.group(1) if cisco_ip else None
            metadata['http_status'] = None
            metadata['http_method'] = None
            metadata['url_path'] = None
            metadata['user_agent'] = None

            # Cisco timestamp: Jun 01 2024 10:00:01
            ts_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})', log)
            if ts_match:
                try:
                    from datetime import datetime as dt
                    metadata['timestamp'] = dt.strptime(ts_match.group(1), "%b %d %Y %H:%M:%S")
                except ValueError:
                    metadata['timestamp'] = None
            else:
                metadata['timestamp'] = None

        else:
            # --- Apache / standard format ---
            ip_match = self.ip_pattern.search(log)
            metadata['source_ip'] = ip_match.group() if ip_match else None

            status_match = re.search(r'"\s+(\d{3})\s+', log)
            metadata['http_status'] = int(status_match.group(1)) if status_match else None

            method_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+', log)
            metadata['http_method'] = method_match.group(1) if method_match else None

            url_match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)', log)
            metadata['url_path'] = url_match.group(1) if url_match else None

            ua_match = re.search(r'"([^"]*(?:Mozilla|curl|wget|python|scanner)[^"]*)"', log, re.I)
            metadata['user_agent'] = ua_match.group(1) if ua_match else None

            # Apache timestamp
            ts_match = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', log)
            if ts_match:
                try:
                    from datetime import datetime as dt
                    metadata['timestamp'] = dt.strptime(ts_match.group(1), "%d/%b/%Y:%H:%M:%S")
                except ValueError:
                    metadata['timestamp'] = None
            else:
                metadata['timestamp'] = None

        return metadata


# -------------------------
# Drain3 Config Optimization
# -------------------------

def get_optimized_drain_config():
    config = TemplateMinerConfig()

    # Optimize for security logs
    config.drain_depth = 5
    config.drain_sim_th = 0.5
    config.drain_max_children = 150
    config.drain_max_clusters = 2000

    # Corrected Masking Rules using MaskingInstruction objects
    config.masking_instructions = [
        MaskingInstruction(pattern=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", mask_with="<IP>"),
        MaskingInstruction(pattern=r"\d{4}-\d{2}-\d{2}", mask_with="<DATE>"),
        MaskingInstruction(pattern=r"\d{2}:\d{2}:\d{2}", mask_with="<TIME>"),
        MaskingInstruction(pattern=r"0x[0-9a-fA-F]+", mask_with="<HEX>"),
        MaskingInstruction(pattern=r"port\s+\d+", mask_with="port <PORT>"),
        MaskingInstruction(pattern=r"\[\d+\]", mask_with="[<PID>]"),
    ]

    return config


# -------------------------
# Embedding Cache
# -------------------------

class EmbeddingCache:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def get_embedding(self, text):
        """Get embedding with caching"""
        cache_key = hashlib.md5(text.encode()).hexdigest()

        if cache_key in self.cache:
            return self.cache[cache_key]

        emb = self.client.embeddings.create(
            model="text-embedding-3-small",
            input=text
        )
        vector = emb.data[0].embedding
        self.cache[cache_key] = vector

        return vector

    def get_batch_embeddings(self, texts, batch_size=100):
        """Get embeddings in batches"""
        results = {}
        uncached = []
        uncached_keys = []

        # Check cache first
        for text in texts:
            cache_key = hashlib.md5(text.encode()).hexdigest()
            if cache_key in self.cache:
                results[text] = self.cache[cache_key]
            else:
                uncached.append(text)
                uncached_keys.append(cache_key)

        # Batch embed uncached
        for i in range(0, len(uncached), batch_size):
            batch = uncached[i:i + batch_size]
            batch_keys = uncached_keys[i:i + batch_size]

            emb = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=batch
            )

            for j, item in enumerate(emb.data):
                self.cache[batch_keys[j]] = item.embedding
                results[batch[j]] = item.embedding

        return results


# -------------------------
# Attack Context Analyzer
# -------------------------

class AttackContextAnalyzer:
    """Analyze attack context for better classification"""

    def __init__(self):
        self.ip_history = defaultdict(list)
        self.attack_chains = []

    def add_event(self, ip, attacks, timestamp=None):
        """Add an event to the IP history"""
        self.ip_history[ip].append({
            "attacks": attacks,
            "timestamp": timestamp or datetime.now()
        })

    def get_ip_threat_score(self, ip):
        """Calculate threat score for an IP based on history"""
        if ip not in self.ip_history:
            return 0

        events = self.ip_history[ip]

        # Factors:
        # 1. Number of events
        event_count = len(events)

        # 2. Diversity of attack types
        all_attacks = set()
        for event in events:
            all_attacks.update(event["attacks"])
        attack_diversity = len(all_attacks)

        # 3. Max severity
        max_severity = 0
        for attack in all_attacks:
            if attack in ATTACK_TAXONOMY:
                max_severity = max(max_severity, ATTACK_TAXONOMY[attack]["severity"])

        # Calculate score
        score = min(100, (
                (event_count * 2) +
                (attack_diversity * 10) +
                (max_severity * 5)
        ))

        return score

    def detect_attack_chain(self, ip):
        """Detect multi-stage attack patterns"""
        if ip not in self.ip_history:
            return None

        events = self.ip_history[ip]
        all_attacks = set()
        for event in events:
            all_attacks.update(event["attacks"])

        chains = []

        # Recon → Exploitation chain
        recon_attacks = {"vulnerability_scanner", "directory_enumeration",
                         "web_fingerprinting", "sensitive_file_probe"}
        exploit_attacks = {"sql_injection", "xss_reflected", "command_injection",
                           "path_traversal", "lfi", "rfi"}

        if all_attacks & recon_attacks and all_attacks & exploit_attacks:
            chains.append("recon_to_exploit")

        # Credential attack chain
        cred_attacks = {"brute_force_ssh", "brute_force_web", "credential_stuffing", "password_spray"}

        if all_attacks & cred_attacks and len(events) > 10:
            chains.append("CREDENTIAL_ATTACK")

        return chains if chains else None


# -------------------------
# Main Training Script
# -------------------------

def train():
    print("=" * 60)
    print("SECURITY LOG TRAINING - ENHANCED VERSION")
    print("=" * 60)

    # Initialize components
    detector = AttackDetector()
    normalizer = LogNormalizer()
    # context_analyzer = AttackContextAnalyzer()
    embedding_cache = EmbeddingCache(client)

    config = get_optimized_drain_config()
    template_miner = TemplateMiner(config=config)

    # ChromaDB
    chroma_client = chromadb.PersistentClient(path="./chroma_db_v2")

    # Delete old collection if exists
    try:
        chroma_client.delete_collection(name="attack_templates_v2")
    except:
        pass

    collection = chroma_client.create_collection(
        name="attack_templates_v2",
        metadata={"description": "Enhanced security log templates"}
    )

    # Load logs
    with open("training_logs.txt") as f:
        logs = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(logs)} log entries")

    # Statistics
    stats = {
        "total": len(logs),
        "attack_counts": defaultdict(int),
        "severity_distribution": defaultdict(int),
        "unique_templates": set(),
        "unique_ips": set()
    }

    # Process logs
    documents = []
    embeddings = []
    metadatas = []
    ids = []

    print("\nProcessing logs...")

    for i, log in enumerate(logs):
        if i % 500 == 0:
            print(f"  Processed {i}/{len(logs)} logs...")

        # Normalize log
        normalized_log = normalizer.normalize(log)

        # Extract template with Drain3
        result = template_miner.add_log_message(normalized_log)
        template = result["template_mined"]

        # Detect attacks
        attacks = detector.detect(log)
        severity = detector.get_severity(attacks)
        mitre = detector.get_mitre_tactics(attacks)

        # Extract metadata
        metadata = normalizer.extract_metadata(log)

        # Update context analyzer
        if metadata['source_ip']:
            # context_analyzer.add_event(metadata['source_ip'], attacks)
            stats["unique_ips"].add(metadata['source_ip'])

        # Update stats
        for attack in attacks:
            stats["attack_counts"][attack] += 1
        stats["severity_distribution"][severity] += 1
        stats["unique_templates"].add(template)

        attack_type = ",".join(attacks)
        category = ATTACK_TAXONOMY.get(attacks[0], {}).get("category", "unknown") if attacks else "unknown"
        method = metadata.get("http_method", "unknown")
        status = metadata.get("http_status", "0")

        embedding_text = f"""
        Log Template: {template}
        Attack Type: {attack_type}
        Category: {category}
        HTTP Method: {method}
        HTTP Status: {status}
        """

        documents.append(embedding_text.strip())

        metadatas.append({
            "template": template,
            "attacks": attack_type,
            "severity": int(severity),
            "mitre_tactics": str(",".join(mitre)) if mitre else "",
            "category": str(category),
            "http_status": str(status),
            "http_method": str(method),
        })

        ids.append(f"log_{i}")

    # Get embeddings in batches
    print("\nGenerating embeddings...")
    unique_templates = list(set(documents))
    template_embeddings = embedding_cache.get_batch_embeddings(unique_templates)

    # Map embeddings back to documents
    embeddings = [template_embeddings[doc] for doc in documents]

    # Store in ChromaDB
    print("\nStoring in ChromaDB...")
    batch_size = 500
    for i in range(0, len(documents), batch_size):
        collection.add(
            documents=documents[i:i + batch_size],
            embeddings=embeddings[i:i + batch_size],
            metadatas=metadatas[i:i + batch_size],
            ids=ids[i:i + batch_size]
        )
        print(f"  Stored batch {i // batch_size + 1}/{(len(documents) - 1) // batch_size + 1}")

    # Print statistics
    print("\n" + "=" * 60)
    print("TRAINING STATISTICS")
    print("=" * 60)

    print(f"\nTotal logs processed: {stats['total']}")
    print(f"Unique templates: {len(stats['unique_templates'])}")
    print(f"Unique IPs: {len(stats['unique_ips'])}")

    print("\nAttack Type Distribution:")
    for attack, count in sorted(stats["attack_counts"].items(),
                                key=lambda x: x[1], reverse=True)[:20]:
        severity = ATTACK_TAXONOMY.get(attack, {}).get("severity", 0)
        print(f"  {attack}: {count} (severity: {severity})")

    print("\nSeverity Distribution:")
    for severity in range(11):
        if stats["severity_distribution"][severity] > 0:
            print(f"  Severity {severity}: {stats['severity_distribution'][severity]}")

    # Analyze high-threat IPs
    # print("\nHigh-Threat IPs:")
    # ip_scores = []
    # for ip in stats["unique_ips"]:
    #     score = context_analyzer.get_ip_threat_score(ip)
    #     if score > 20:  # Threshold
    #         chains = context_analyzer.detect_attack_chain(ip)
    #         ip_scores.append((ip, score, chains))
    #
    # for ip, score, chains in sorted(ip_scores, key=lambda x: x[1], reverse=True)[:10]:
    #     chain_str = f" [Chains: {', '.join(chains)}]" if chains else ""
    #     print(f"  {ip}: Score {score}{chain_str}")
    #
    # print("\n" + "=" * 60)
    # print("TRAINING COMPLETED SUCCESSFULLY")
    # print("=" * 60)

    return stats


if __name__ == "__main__":
    train()