pentest_tools = [
    "Nikto", "OpenVAS", "Acunetix", "Nessus", "Burp Suite", "W3af", "Grabber", "Wapiti", "Vega",
    "Websecurify", "Ratproxy", "wfuzz", "Gobuster", "Dirb", "sn1per", "xsser", "cmsmap", "WPScan",
    "JoomScan", "WhatWeb", "FuzzDB", "Brakeman", "Skipfish", "Lynis", "Retire.js", "Uniscan",
    "CMS Explorer", "BeEF", "Havij", "Exploit Pack", "Nexpose", "QualysGuard", "IronWASP",
    "WebScarab", "YASW", "Vulnix", "Watcher", "Proxy", "Security Monkey", "WebReaver",
    "Ardas Lair", "VulnDetect", "NETSPARKER", "V3n0M", "Recon-ng", "DotDotPwn", "Shodan",
    "Spaghetti", "Armitage", "Triton", "RIPS", "wascan", "WPSeku", "XAttacker", "Kracken",
    "WAVSEP", "Powerfuzzer", "Yuki Chan", "wig", "Wapka", "TesserCap", "NoSQLMap", "Panoptic",
    "Kiuwan", "Fuzzapi", "Jok3r", "Kube-Hunter", "NexDOS", "Pompem", "Prowler", "Spartan",
    "Trivy", "Vane", "Web Application Firewall Detection", "Wap", "WPForce", "XRay",
    "Zed Attack Proxy", "ZAP", "Scout2", "Grendel-Scan", "XSStrike", "Arachni", "Raccoon",
    "Photon", "CMSeeK", "Sh00t", "Dagda", "Santoku", "WATOBO", "Crawley", "Dawnscanner",
    "Garmr", "Amass", "Gitrob", "Kadabra", "Dracnmap", "Droopescan", "Bluto", "EyeWitness",
    "ECS-Hash", "Hawk", "Httrack", "lbd", "ZmEu", "WebSlayer", "Tulpar", "W3brute", "DorkNet",
    "Sslstrip", "Joomlavs", "Sslscan", "Cansina", "Yasuo", "Rang3r", "Bleach", "Sakis3G",
    "BlindElephant", "JoomAttacker", "Kadimus", "XSSYA", "Ezsploit", "Hackersh", "ReconDog",
    "Chomp-Scan", "Snitch", "Legion", "ATSCAN", "WebSploit", "Blisqy", "Bypass", "CMS-Garden",
    "Dnsmap", "Fibratus", "Graudit", "HatCloud", "HostMap", "JoomlaScan", "Kerberoast",
    "Liffy", "Metasploit", "NekoBot", "Reconnoitre", "ReelPhish", "Ruler", "SMBMap",
    "Sublist3r", "THC-IPV6", "TheHarvester", "TIDoS", "WPSploit", "Xcat", "Xerosploit",
    "XSpear", "Subfinder", "GitGraber", "VHostScan", "InSpy", "Osmedeus", "LinkFinder",
    "S3Scanner", "ParamSpider", "BeeWASP", "Aquatone", "BBScan", "DAVTest", "XANAX",
    "BashScanner", "CredNinja", "Firewalk", "HTTProbe", "Knockpy", "Leviathan", "MobSF",
    "Pulsar", "Striker", "A2SV", "Brutespray", "Clusterd", "CeWL", "DNSenum",
    "Fingerprintjs2", "Golismero", "Hwacha", "Java-Deserialization-Scanner", "JWT Tool",
    "LazyDroid", "MacSubstrate", "Maltego Teeth", "MassBleed", "MFCuk", "O-Saft", "OWTF",
    "RFP", "Snallygaster", "SMTPTerminator", "SpiderFoot", "SQLMate", "SSRFmap", "T50",
    "Th3inspector", "Vulscan", "WAFNinja", "Xposed", "YSoserial", "Zeus-Scanner", "Nmap",
    "Masscan", "Unicornscan", "Hping3", "Netcat", "Ettercap", "Tcpdump", "Wireshark",
    "Aircrack-ng", "Reaver", "Kismet", "Fern WiFi Cracker", "Wifite", "Bettercap", "Responder",
    "Impacket", "BloodHound", "PowerSploit", "Empire", "Cobalt Strike", "FoxyProxy",
    "ProxyChains", "Sqlmap", "sqlninja", "Whitewidow", "Commix", "Inject-X", "Dirstalk",
    "Feroxbuster", "Assetfinder", "Censys", "Google Dorking", "Zphisher",
    "Evilginx2", "Modlishka", "SET", "Rubeus", "Kerbrute", "SMBExec", "CrackMapExec",
    "Patator", "Hydra", "Medusa", "John the Ripper", "Hashcat", "Rainbow Crack",
    "CoWPAtty", "Keimpx", "LDAPSearch", "Ffuf", "Wfing", "Metagoofil", "Eyewitness",
    "AppScan", "Shadow Scanner", "Dradis", "Faraday", "FindBugs", "SonarQube",
    "WAFW00F", "TLS Fingerprinting", "CertGraph", "Kadabra", "DeepViolet", "RapidScan",
    "SSLyze", "TestSSL", "TLSSLed"
]

rce_commands = [
    # 🖥️ Linux-Based RCE Commands
    r"\bwhoami\b", r"\bid\b", r"\buname -a\b", r"\bcat /etc/passwd\b", r"\bls -la /root/\b",
    r"\bcurl http[s]?://.+? | sh\b", r"\bwget http[s]?://.+? -O - | bash\b",
    r"\bnc -e /bin/sh .+? \d+\b", r"\bpython -c 'import os; os.system\(\"/bin/bash\"\)'\b",
    r"\bperl -e 'exec \"/bin/sh\";'\b", r"\becho 'bash -i >& /dev/tcp/.+?/\d+ 0>&1' | bash\b",

    # 🖥️ Windows-Based RCE Commands
    r"\bwhoami\b", r"\bsysteminfo\b", r"\bdir C:\\Users\\Administrator\\Desktop\b",
    r"\btype C:\\Windows\\System32\\drivers\\etc\\hosts\b",
    r"\bpowershell -c \"Invoke-WebRequest -Uri '.+?' -OutFile '.+?'\"\b",
    r"\bcertutil -urlcache -split -f http[s]?://.+? .+?\b",
    r"\bwmic process call create \"cmd.exe /c .+?\"\b",
    r"\brundll32.exe javascript:\\\"\\..\\mshtml,RunHTMLApplication\\\"\b",

    # 🔥 Web-Based RCE Payloads
    r"\bhttp[s]?://.+?index.php\?cmd=\b", r"<\?php system\(\$_GET\['cmd'\]\); \?>",
    r"\bcurl -X POST -d \"cmd=.+?\" http[s]?://.+?\b",
    r"\becho 'bash -i >& /dev/tcp/.+?/\d+ 0>&1' | bash\b"
]

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

xss_patterns = [
    # 🖥️ Standard Script Injection
    r"<script.*?>.*?</script>",  # Detects standard script tags
    r"javascript:.*?",  # Identifies JavaScript protocol exploitation
    r"vbscript:.*?",  # Flags VBScript-based injections
    r"data:text/html;base64,.*?",  # Detects base64-encoded script injections

    # 🖥️ Event Handler Exploitation
    r"onerror=.*?",  # Image-based XSS exploitation
    r"onload=.*?",  # Automated execution payloads
    r"onclick=.*?",  # User interaction-triggered XSS
    r"onmouseover=.*?",  # Hover-based script execution
    r"onfocus=.*?",  # Focus-triggered payload execution
    r"onmessage=.*?",  # Abuse of postMessage event handler

    # 🖥️ Encoded & Obfuscated Payloads
    r"%3Cscript%3E.*?%3C/script%3E",  # URL-encoded XSS
    r"&#x3C;script&#x3E;.*?&#x3C;/script&#x3E;",  # Hexadecimal-encoded scripts
    r"eval\(.*?\)",  # Prevents eval-based execution
    r"document.cookie",  # Sensitive data exfiltration attempts
    r"window.location=.*?",  # Forced redirects using JavaScript
    r"setTimeout\(.*?\)",  # Delayed execution attack
    r"setInterval\(.*?\)",  # Continuous execution attack

    # 🖥️ HTML Element Abuse
    r"<iframe src=.*?>",  # Iframe-based attacks
    r"<img src=.*? onerror=.*?>",  # Image-triggered XSS payloads
    r"<object data=.*?>",  # Malicious object-based execution
    r"<embed src=.*?>",  # Embedded exploit attempts
    r"<link rel=\"stylesheet\" href=\"javascript:.*?>",  # Malicious stylesheet injection
    r"<meta http-equiv=\"refresh\" content=\"0;url=javascript:.*?>",  # Meta-refresh script injection

    # 🖥️ JavaScript Function Manipulation
    r"Function\('alert\(1\)'\)\(\)",  # Inline function execution
    r"console.log\(alert\(1\)\)",  # Console-based XSS trick
    r"Object.defineProperty\(document,'cookie',{get:function(){alert\(1\)}}\);",  # Property manipulation attack
]
