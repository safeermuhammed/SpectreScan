import re
import base64
from colorama import Fore, Style, init
from pentesttools import pentest_tools, xss_patterns


# Initialize Colorama
init(autoreset=True)

bot_patterns = [
    r"bot|crawler|spider",  # Detects known bots in User-Agent strings
    r"\bpython-requests\b",  # Flags scripted HTTP requests
    r"\bcurl\b", r"\bwget\b",  # Identifies CLI-based request automation
    r"\bheadless\b",  # Detects headless browsers (Selenium, Puppeteer)
    r"\bnet::ERR_BLOCKED_BY_CLIENT\b",  # Flags bot-blocking errors in logs
]


encoded_patterns = [
    r"%3Cscript%3E.*?%3C/script%3E",  # URL-encoded XSS
    r"&#x3C;script&#x3E;.*?&#x3C;/script&#x3E;",  # Hexadecimal-encoded XSS
    r"(?i)(eval|exec)\(base64_decode\(.*?\)\)",  # Encoded PHP attacks
    r"(?i)base64_decode\(.*?\)",  # Base64-based obfuscation
    r"(?i)data:text/html;base64,.*?",  # Base64 payloads embedded in requests
    r"(?i)document\.cookie",  # Sensitive data exfiltration
]

def detect_encoded_attacks(log_entries, encoded_patterns):
    for log_entry in log_entries:
        log_entry = log_entry.strip()

        # Check if log entry contains encoded payloads
        if any(re.search(pattern, log_entry, re.IGNORECASE) for pattern in encoded_patterns):
            print(f"{Fore.RED}⚠️ Encoded Attack Attempt Detected: {log_entry}{Style.RESET_ALL}")

        # Base64 Decoding Check (if applicable)
        try:
            decoded_entry = base64.b64decode(log_entry).decode("utf-8")
            if any(re.search(pattern, decoded_entry, re.IGNORECASE) for pattern in encoded_patterns):
                print(f"{Fore.RED}🚨 Encoded Base64 Attack Detected (Decoded): {decoded_entry}{Style.RESET_ALL}")
        except Exception:
            pass  # Ignore errors for invalid Base64 inputs

# 🔍 Hardcoded SQL Injection Patterns (No External File)
sqli_patterns = [
    r"\bUNION\s+SELECT\b", r"\bOR\s+1=1\b", r"\bSELECT\s+\*\s+FROM\b",
    r"\bDROP\s+TABLE\b", r"\bINSERT\s+INTO\b", r"\bUPDATE\s+SET\b",
    r"\bSLEEP\(\d+\)\b", r"\bGROUP\s+BY\b\s+--\b"
]

# 🔍 Hardcoded RCE Command Patterns
rce_commands = [
# 🖥️ Linux-Based RCE Commands
    r"\bwhoami\b", r"\buname -a\b", r"\bcat /etc/passwd\b",
    r"\bls -la\b", r"\bpwd\b", r"\bnetstat -antp\b", r"\bps aux\b",
    r"\bchmod 777\b", r"\bchown root\b", r"\bsudo .*?\b",
    r"\bapt-get install\b", r"\byum install\b", r"\bcurl http[s]?://.+? | sh\b",
    r"\bwget http[s]?://.+? -O - | bash\b", r"\bnc -e /bin/sh .+? \d+\b",
    r"\bpython -c\b", r"\bperl -e\b", r"\bpowershell\b", r"\bcertutil\b",

    # 🖥️ Windows-Based RCE Commands
    r"\bsysteminfo\b", r"\bdir C:\\Users\\Administrator\\Desktop\b",
    r"\btype C:\\Windows\\System32\\drivers\\etc\\hosts\b",
    r"\bpowershell -c \"Invoke-WebRequest -Uri '.+?' -OutFile '.+?'\"\b",
    r"\bcertutil -urlcache -split -f http[s]?://.+? .+?\b",
    r"\bwmic process call create \"cmd.exe /c .+?\"\b",
    r"\brundll32.exe javascript:\\\"\\..\\mshtml,RunHTMLApplication\\\"\b",
    r"\bnet user\b", r"\btasklist\b", r"\bsc query\b",
    r"\breg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\b",

    # 🔥 Web-Based RCE Payloads
    r"\bhttp[s]?://.+?index.php\?cmd=\b", r"<\?php system\(\$_GET\['cmd'\]\); \?>",
    r"curl -X POST -d \"cmd=ls\" http[s]?://.+?\b", r"echo 'bash -i >& /dev/tcp/.+?/\d+ 0>&1' | bash\b",
    r"\bping -c 5 .+?\b", r"\bwget .+?; bash\b", r"\bmkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc .+? \d+ > /tmp/f\b"
]

# 🔍 Hardcoded Header Manipulation Patterns
header_patterns = [
    "X-Forwarded-For:", "Origin:", "Referer:", "User-Agent:", "Authorization: Bearer"
]

# 🔍 Hardcoded Malicious File Extensions
malicious_file_extensions = [
# 🖥️ Executable & Script-Based Extensions
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".msi",

    # 🔥 Web Shell & Server-Side Execution Extensions
    ".php", ".phtml", ".phar", ".asp", ".aspx", ".asa", ".cer",
    ".jsp", ".jspx", ".jsw", ".jsv", ".cgi", ".pl", ".pm", ".cfm", ".cfml", ".cfc",

    # 📂 Archive & Compressed File Extensions (Payload Delivery)
    ".zip", ".rar", ".tar", ".gz", ".7z", ".iso", ".img", ".jar",

    # 📜 Document-Based Exploits
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf",

    # 🎨 Image & Media-Based Exploits
    ".svg", ".gif", ".png", ".jpg", ".mp4", ".avi", ".mov",

    # 🛠 Other Dangerous Extensions
    ".dll", ".sys", ".deb", ".rpm", ".py", ".rb", ".lua"
]

# 🛠 Function to Detect SQL Injection Attempts
def detect_sql_injection(log_entries, sqli_patterns):
    for log_entry in log_entries:
        log_entry = log_entry.strip()
        if any(re.search(pattern, log_entry, re.IGNORECASE) for pattern in sqli_patterns):
            print(f"{Fore.YELLOW}⚠️ SQL Injection Attempt Detected: {log_entry}{Style.RESET_ALL}")

# 🛠 Function to Detect Remote Code Execution (RCE) Attempts
def detect_rce_commands(log_entries, rce_commands):
    for log_entry in log_entries:
        log_entry = log_entry.strip()
        if any(re.search(pattern, log_entry, re.IGNORECASE) for pattern in rce_commands):
            print(f"{Fore.BLUE}⚠️ Remote Code Execution (RCE) Attempt Detected: {log_entry}{Style.RESET_ALL}")

# 🛠 Function to Detect Header Manipulation Attempts
def detect_header_manipulation(log_entries, header_patterns):
    for log_entry in log_entries:
        log_entry = log_entry.strip()
        if any(pattern.lower() in log_entry.lower() for pattern in header_patterns):
            print(f"{Fore.CYAN}⚠️ Suspicious Header Manipulation Detected: {log_entry}{Style.RESET_ALL}")

# 🛠 Function to Detect Malicious File Uploads
def detect_malicious_uploads(log_entries, malicious_extensions):
    for log_entry in log_entries:
        log_entry = log_entry.strip()
        if any(ext in log_entry.lower() and ("filename=" in log_entry.lower() or "/upload" in log_entry.lower()) for ext in malicious_extensions):
            print(f"{Fore.RED}🚨 Malicious File Upload Detected: {log_entry}{Style.RESET_ALL}")



print("🔍 Paste attack logs below (Enter 'DONE' when finished):")
user_logs = []
while True:
    log_entry = input()
    if log_entry.strip().upper() == "DONE":
        break
    user_logs.append(log_entry)


def detect_pentest_tools(log_entries, pentest_tools):
    for log_entry in log_entries:
        log_entry = log_entry.strip()

        if any(tool.lower() in log_entry.lower() for tool in pentest_tools):
            print(f"{Fore.RED}🚨 Penetration Testing Tool Detected: {log_entry}{Style.RESET_ALL}")

def detect_xss_attacks(log_entries, xss_patterns):
    for log_entry in log_entries:
        log_entry = log_entry.strip()

        # Strict regex matching ensures accurate flagging with minimal false positives
        if any(re.search(pattern, log_entry, re.IGNORECASE) for pattern in xss_patterns):
            print(f"{Fore.YELLOW}⚠️ Cross-Site Scripting (XSS) Attempt Detected: {log_entry}{Style.RESET_ALL}")

def detect_bots(log_entries, bot_patterns):
    for log_entry in log_entries:
        log_entry = log_entry.strip()

        # Check for bot-related indicators
        if any(re.search(pattern, log_entry, re.IGNORECASE) for pattern in bot_patterns):
            print(f"{Fore.RED}🚨 Bot Activity Detected: {log_entry}{Style.RESET_ALL}")


detect_sql_injection(user_logs, sqli_patterns)
detect_rce_commands(user_logs, rce_commands)
detect_header_manipulation(user_logs, header_patterns)
detect_malicious_uploads(user_logs, malicious_file_extensions)
detect_pentest_tools(user_logs,pentest_tools)
detect_xss_attacks(user_logs,xss_patterns)
detect_encoded_attacks(user_logs,encoded_patterns)
detect_bots(user_logs,bot_patterns)
