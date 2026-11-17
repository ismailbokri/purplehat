"""One-shot translator: rewrite palnner/checklist.json content into English.

Content-only translation. It never touches the field KEYS ("Tests", "Catégorie",
"Vulnérabilité attendue", …) nor the category names, because the backend
(checklist_tool.py, bootstrap.py, report generation) matches on those exact
French strings. Only the human-readable VALUES are rewritten.

The script is idempotent-ish: values already in English (not in the maps) are
left as-is, so re-running after a manual tweak is safe.

Run from repo root:  python scripts/translate_checklist.py
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
JSON_PATH = ROOT / "palnner" / "checklist.json"

# Keys whose VALUES carry category/identity meaning — never translate these.
_FROZEN_KEYS = {"ID", "Catégorie"}

# ── Boilerplate placeholders (repeated hundreds of times) ─────────────────────
BOILERPLATE = {
    "A compléter par le consultant pendant la mission":
        "To be completed by the consultant during the engagement",
    "A compléter par le consultant si le chef de projet a fait un commentaire":
        "To be completed by the consultant if the project lead left a comment",
    "A compléter par le Chef de projet":
        "To be completed by the project lead",
    "A compléter par le consultant avec ses éventuelles propositions d'amélioration par rapport à ce test":
        "To be completed by the consultant with any improvement suggestions for this test",
    # Common short result / comment strings
    "Sensible / Non sensible": "Vulnerable / Not vulnerable",
    "Plus de détails": "More details",
    "Liste des outils": "List of tools",
    "Comment le faire ?": "How to do it?",
    "Comment le faire/outils ?": "How to do it / which tools?",
    "Protégée / Non protégée": "Protected / Not protected",
    "Activé / Non activé": "Enabled / Not enabled",
    "ON / OFF": "ON / OFF",
    "GET / POST": "GET / POST",
    "Bypass / Pas de bypass": "Bypass / No bypass",
    "Possible / impossible": "Possible / Not possible",
    "Vulnérable  / Non vunérable": "Vulnerable / Not vulnerable",
}

# ── Per-test translations, keyed by test ID. Each maps French→English for the
#    human-readable fields of that test. Field keys stay French. ──────────────
# Only non-null, non-boilerplate values need an entry; anything missing is left
# unchanged (and reported at the end so nothing is silently skipped).
TRANSLATIONS = {
    # placeholder; populated below by _T(...)
}


def _T(test_id, **fr_to_en):
    TRANSLATIONS[str(test_id)] = fr_to_en


# ─────────────────────────── Découverte (1–13) ──────────────────────────────
_T(1,
   Tests="Collect Whois information",
   Outils="OSINT",
   **{"Réf. Procédure": "The OSINT Framework site lists many tools",
      "Commentaires": "Which OSINT tools are available?",
      "Résultat attendu": "Whois information, disclosing or not disclosing confidential information",
      "Vulnérabilité attendue": "Whois information disclosing confidential information",
      "Bonne pratique attendu": "Whois information not disclosing confidential information"})
_T(2,
   Tests="Identify the network components (FW, WAF, routers, etc.) of the application platform",
   Outils="Traceroute\nNmap",
   **{"Résultat attendu": "Network architecture of the target application platform",
      "Vulnérabilité attendue": "Insufficiently secured network design of the application platform"})
_T(3,
   Tests="Check whether the enabled services are insecure / dangerous / unnecessary",
   Outils="Nessus\nNmap",
   **{"Résultat attendu": "List of insecure / dangerous services",
      "Vulnérabilité attendue": "Dangerous / insecure / potentially unnecessary services enabled"})
_T(4,
   Tests="Check whether the platform's administration services are reachable from the \"Users\" network / the Internet",
   Outils="NMAP\nTelnet\nSSH\nBrowser\nNessus",
   **{"Résultat attendu": "Access to administration services",
      "Vulnérabilité attendue": "Administration services of the application platform reachable from the \"Users\" network / the Internet",
      "Bonne pratique attendu": "Administration services of the application platform reachable from the \"Users\" network / the Internet"})
_T(5,
   Tests="Identify the operating systems, applications, services, technologies, library versions, etc. in use",
   Outils="Nmap\nTelnet\nNessus",
   **{"Résultat attendu": "Operating systems, applications, services, technologies, etc.",
      "Vulnérabilité attendue": "Disclosure of information about operating systems, applications, services, library versions, etc.",
      "Bonne pratique attendu": "Application platform that does not disclose the types and versions of the services and systems in use"})
_T(6,
   Tests="Look for previews, backups, and older versions of the application available online",
   Outils="waybackurls\nbfac",
   **{"Vulnérabilité attendue": "To be determined based on what we find",
      "Bonne pratique attendu": "No critical data publicly available on the Internet"})
_T(7,
   Tests="Check whether the application is hosted on a shared server",
   **{"Résultat attendu": "Shared server\nDedicated server",
      "Vulnérabilité attendue": "Use of a shared server",
      "Bonne pratique attendu": "Use of a dedicated server"})
_T(8,
   Tests="Check whether the application responds to ping from the Internet",
   **{"Vulnérabilité attendue": "ICMP protocol enabled from the Internet"})
_T(9,
   Tests="Enumerate subdomains",
   Outils="Sublist3r\nAmass",
   **{"Résultat attendu": "List of subdomains, if any"})
_T(10,
   Tests="Check for the presence of /robots.txt /crossdomain.xml /clientaccesspolicy.xml /phpinfo.php /sitemap.xml and /.well-known/",
   **{"Réf. Procédure": "dirsearch, dirb, etc.",
      "Commentaires": "List of tools",
      "Résultat attendu": "Files present / not present"})
_T(11,
   Tests="Check for the presence of /.git",
   Outils="gitdumper",
   **{"Résultat attendu": "Directory present / absent",
      "Vulnérabilité attendue": "Access to the application's development history.",
      "Bonne pratique attendu": "Directory not present on the application"})
_T(12,
   Tests="Scan for VHOSTs",
   Outils="VHostScan",
   **{"Résultat attendu": "List of vhosts, if any"})
_T(13,
   Tests="Search Shodan for the IPs found earlier",
   Outils="Shodan",
   **{"Réf. Procédure": "Any approach you prefer",
      "Commentaires": "Is Shodan enough, or do we need other similar tools?"})

# ───────────────────── Pré-authentification (14–54) ──────────────────────────
_T(14,
   Tests="Check whether the application is accessible to its users only over a secure protocol",
   **{"Vulnérabilité attendue": "Use of an unencrypted communication protocol\nTraffic transmitted in clear text between the client and the server\nApplication accessible over HTTP",
      "Bonne pratique attendu": "Use of an encrypted communication protocol\nTraffic encrypted between the client and the server\nApplication accessible only over HTTPS"})
_T(15,
   Tests="Check whether the application is accessible to its administrators only over a secure protocol",
   **{"Vulnérabilité attendue": "Use of an unencrypted administration protocol",
      "Bonne pratique attendu": "N/A"})
_T(16,
   Tests="Check whether there is a mechanism to detect and block network scans and application-layer attacks",
   **{"Résultat attendu": "WAF present / absent",
      "Vulnérabilité attendue": "No mechanism to detect and block network scans and application-layer attacks",
      "Bonne pratique attendu": "Application platform protected by a mechanism that detects and blocks network scans and application-layer attacks"})
_T(17,
   Tests="Check whether the WAF is misconfigured (generation of inappropriate error messages, etc.):\nGET @www.example.com HTTP/1.1\nGET @localhost HTTP/1.1\nGET :@localhost HTTP/1.1\nGET :@localhost:443 HTTP/1.1\n...",
   **{"Réf. Procédure": "Using nc or telnet, send GET requests and check the responses",
      "Commentaires": "More details",
      "Résultat attendu": "Well configured / misconfigured",
      "Vulnérabilité attendue": "WAF misconfiguration"})
_T(18,
   Tests="Review error messages and try to exploit them (technologies in use, internal IP addresses, etc.)",
   Outils="Nessus\nNmap\nBrowser",
   **{"Résultat attendu": "Information disclosed about the web application",
      "Vulnérabilité attendue": "Information disclosure in error messages\nUse of default error pages",
      "Bonne pratique attendu": "Application that does not disclose information in error messages"})
_T(19,
   Tests="Review the HTML source and try to extract confidential / useful information (technologies in use, internal IP addresses, passwords, etc.)",
   **{"Vulnérabilité attendue": "Information disclosure in the HTML source"})
_T(20,
   Tests="Where administration settings are accessible, check whether they are default or hardened",
   **{"Résultat attendu": "Default settings\nHardened settings",
      "Vulnérabilité attendue": "Use of the default administration configuration"})
_T(21,
   Tests="Identify known vulnerabilities affecting the types and versions of the identified components",
   **{"Résultat attendu": "Types and versions of the web servers, PHP, etc.",
      "Vulnérabilité attendue": "Use of vulnerable versions of application components (Apache server, PHP, etc.)\nWeb server vulnerable to ShellShock\nWeb server vulnerable to ...",
      "Bonne pratique attendu": "Use of patched application components"})
_T(22,
   Tests="Check the SSL certificate:\n- What is its version?\n- Is it valid (date)?\n- Is the SSL certificate an \"EV-SSL\" certificate?\n- Was it signed by a recognised and trusted certificate authority (Issuer field)?\n- Is it issued for the site in question (\"Issued to\" field)?\n- Is the certificate signature algorithm strong (\"Certificate signature algorithm\" field)?\n- Is it generated for a single DNS name or for several?\n- Is it a Single-domain, Multi-domain (UCC) or Wildcard certificate?",
   Outils="Manual\nAcunetix",
   **{"Résultat attendu": "Information about the certificate",
      "Vulnérabilité attendue": "SSL certificate not compliant with security best practices",
      "Bonne pratique attendu": "SSL certificate compliant with security best practices"})
_T(23,
   Tests="Check the SSL configuration:\n- Are the allowed protocols strong?\n- Are the allowed algorithms strong?\n- Is the HTTP Strict Transport Security (HSTS) header enabled in the web server's response?",
   **{"Vulnérabilité attendue": "Insufficiently secured SSL protocol configuration",
      "Bonne pratique attendu": "Secure SSL protocol configuration"})
_T(24,
   Tests="Check whether there are unnecessary resources on the server (default pages, test pages, etc.)",
   **{"Résultat attendu": "List of unnecessary resources on the server",
      "Vulnérabilité attendue": "Presence of unnecessary resources\nBackup file publicly accessible"})
_T(25,
   Tests="Determine the HTTP methods allowed on the web applications",
   Outils="Nessus\nNmap\nTelnet",
   **{"Résultat attendu": "HTTP methods allowed on the web applications",
      "Vulnérabilité attendue": "Dangerous / unnecessary HTTP methods allowed",
      "Bonne pratique attendu": "Dangerous HTTP methods not allowed"})
_T(26,
   Tests="Determine whether directory listing is enabled on the web application",
   Outils="Browser\nBurp\nAcunetix\nNessus",
   **{"Résultat attendu": "Directory listing enabled / not enabled",
      "Vulnérabilité attendue": "Directory listing enabled on the web application",
      "Bonne pratique attendu": "Directory listing disabled on the web application"})
_T(27,
   Tests="Determine whether the application is affected by directory traversal",
   **{"Résultat attendu": "Directory traversal possible / not possible",
      "Vulnérabilité attendue": "Web applications vulnerable to directory traversal"})
_T(28,
   Tests="Check whether the application discloses information about valid user identifiers",
   **{"Vulnérabilité attendue": "Application disclosing information about valid user identifiers\nUser account enumeration possible",
      "Bonne pratique attendu": "Application that does not disclose information about valid user identifiers"})
_T(29,
   Tests="Check whether the \"AUTOCOMPLETE\" attribute is set to \"ON\"",
   **{"Résultat attendu": "ON / OFF",
      "Vulnérabilité attendue": "Authentication data can be saved in the browser",
      "Bonne pratique attendu": "\"AUTOCOMPLETE\" attribute set to \"OFF\""})
_T(30,
   Tests="Check whether the application is protected against brute-force attacks",
   **{"Résultat attendu": "Protected / Partially protected / Not protected",
      "Vulnérabilité attendue": "No protection against brute-force attacks\nUse of a weak brute-force protection mechanism",
      "Bonne pratique attendu": "Application protected against brute-force attacks"})
_T(31,
   Tests="SQL Injection",
   **{"Résultat attendu": "Unauthorised execution of SQL queries",
      "Vulnérabilité attendue": "Application vulnerable to SQL injection",
      "Bonne pratique attendu": "Robust filtering of client requests"})
_T(32,
   Tests="Check whether the application is vulnerable to XSS: inject JavaScript, HTML, VBScript, etc.",
   **{"Résultat attendu": "Code injected / not injected",
      "Vulnérabilité attendue": "Application sensitive to Cross-Site Scripting (XSS)\nApplication potentially sensitive to Cross-Site Scripting (XSS)",
      "Bonne pratique attendu": "Robust filtering of dangerous characters"})
_T(33,
   Tests="Check whether the application is vulnerable to other types of injection: XPath injection, CRLF injection (HTTP response splitting), XML injection, JSON injection",
   **{"Vulnérabilité attendue": "Application sensitive to CRLF injection (HTTP response splitting)\nApplication sensitive to ..."})
_T(34,
   Tests="Check whether the application is sensitive to Open Redirect",
   **{"Réf. Procédure": "Manual or any tools you prefer",
      "Commentaires": "More details",
      "Résultat attendu": "Sensitive / not sensitive",
      "Vulnérabilité attendue": "Application sensitive to Open Redirect",
      "Bonne pratique attendu": "Application not sensitive to Open Redirect"})
_T(35,
   Tests="Check whether the server uses default URLs such as /wp-admin.php and /wp-login.php",
   **{"Vulnérabilité attendue": "Use of default URLs"})
_T(36,
   Tests="Check whether the application is protected against URL brute-force attacks",
   **{"Résultat attendu": "Protected / Not protected",
      "Vulnérabilité attendue": "No protection against URL brute-force attacks"})
_T(37,
   Tests="Check whether the server is vulnerable to DoS attacks",
   **{"Vulnérabilité attendue": "Server vulnerable to DoS attacks",
      "Bonne pratique attendu": "Server resistant to DoS attacks"})
_T(38,
   Tests="Fuzz the URL parameters",
   Outils="ffuf\nwfuzz",
   **{"Résultat attendu": "Parameters filtered / errors generated",
      "Vulnérabilité attendue": "Interesting errors generated",
      "Bonne pratique attendu": "Values are filtered"})
_T(39,
   Tests="Check whether the application is vulnerable to OS command injection: inject system commands",
   **{"Résultat attendu": "Commands injected / not injected",
      "Vulnérabilité attendue": "Application sensitive to OS command injection",
      "Bonne pratique attendu": "System commands are filtered"})
_T(40,
   Tests="Check whether the application is vulnerable to SSTI",
   **{"Réf. Procédure": "Manual or any tools you prefer — there are many payloads",
      "Commentaires": "More details",
      "Résultat attendu": "Code injected / not injected",
      "Vulnérabilité attendue": "Application sensitive to SSTI",
      "Bonne pratique attendu": "Templating syntax is filtered"})
_T(41,
   Tests="Check whether the application is vulnerable to HTTP Request Smuggling",
   Outils="Burp Suite HTTP Request Smuggler extension\nsmuggler",
   **{"Résultat attendu": "Vulnerable / not vulnerable",
      "Vulnérabilité attendue": "Application vulnerable to HTTP Request Smuggling",
      "Bonne pratique attendu": "Application not vulnerable to HTTP Request Smuggling"})
_T(42,
   Tests="Check whether the application is vulnerable to SSRF against the IPs/ports discovered earlier",
   Outils="Gopherus",
   **{"Résultat attendu": "Access to internal resources / no access to internal resources",
      "Vulnérabilité attendue": "Application vulnerable to SSRF",
      "Bonne pratique attendu": "The application blocks requests to internal resources"})
_T(43,
   Tests="Test duplicate account creation",
   **{"Résultat attendu": "Account created successfully / creation refused",
      "Vulnérabilité attendue": "Account duplication",
      "Bonne pratique attendu": "The application checks whether the account already exists"})
_T(44,
   Tests="Overwrite an existing user during account creation (test username uniqueness)",
   **{"Réf. Procédure": "Try to register a user with an already-registered login / username / surname",
      "Commentaires": "How to do it?",
      "Résultat attendu": "Existing account overwritten / creation refused",
      "Vulnérabilité attendue": "Overwriting of another user's account",
      "Bonne pratique attendu": "The application checks whether the username already exists"})
_T(45,
   Tests="Check the email verification process",
   **{"Résultat attendu": "No email verification / email verification required",
      "Vulnérabilité attendue": "No email verification",
      "Bonne pratique attendu": "The application enforces email verification"})
_T(46,
   Tests="Creating an account using a long password (> 200) leads to a DoS",
   **{"Résultat attendu": "DoS / password rejected",
      "Vulnérabilité attendue": "Server vulnerable to DoS attacks",
      "Bonne pratique attendu": "The application enforces a maximum password length"})
_T(47,
   Tests="Inject malicious code into the username during account creation")
_T(48,
   Tests="xmlrpc.php DoS and user enumeration",
   Outils="WPScan",
   **{"Résultat attendu": "File exists / does not exist",
      "Vulnérabilité attendue": "Application vulnerable to DoS attacks and user enumeration",
      "Bonne pratique attendu": "File does not exist"})
_T(49,
   Tests="Test SMTP injection if a contact form exists",
   **{"Résultat attendu": "Sensitive / not sensitive",
      "Vulnérabilité attendue": "Application vulnerable to SMTP injection",
      "Bonne pratique attendu": "Robust filtering"})
_T(50,
   Tests="Test whether CORS is properly configured",
   Outils="Corsy",
   **{"Résultat attendu": "Cross-origin access allowed / cross-origin access not allowed",
      "Vulnérabilité attendue": "CORS misconfigured",
      "Bonne pratique attendu": "Correct CORS configuration"})
_T(51,
   Tests="Try to discover hidden parameters",
   Outils="Arjun")
_T(52,
   Tests="Inject HTTP headers to bypass 403 responses",
   Outils="byp4xx",
   **{"Résultat attendu": "Bypass / no bypass",
      "Vulnérabilité attendue": "Access-restriction bypass",
      "Bonne pratique attendu": "The application blocks unauthorised access"})
_T(53,
   Tests="Check for the presence of internal/external numeric IP addresses in the requests")
_T(54,
   Tests="Look for hard-coded API keys and secrets in JavaScript",
   Outils="Burp Suite, find scripts",
   **{"Résultat attendu": "Hard-coded secrets / no hard-coded secrets",
      "Vulnérabilité attendue": "The application contains hard-coded secrets in the JavaScript files",
      "Bonne pratique attendu": "No hard-coded secrets"})

# ───────────────────── Post-authentification (56–107) ────────────────────────
_T(56,
   Tests="For highly sensitive applications, check whether strong authentication is used",
   **{"Résultat attendu": "Strong authentication / \"login + password\" authentication",
      "Vulnérabilité attendue": "Insufficiently secured authentication mechanism",
      "Bonne pratique attendu": "Strong authentication"})
_T(57,
   Tests="Study the password policy in terms of complexity",
   **{"Résultat attendu": "Complex / not complex",
      "Vulnérabilité attendue": "Insecure password policy",
      "Bonne pratique attendu": "Password policy deemed satisfactory"})
_T(58,
   Tests="Check whether the number of failed authentication attempts with the same account is limited",
   **{"Résultat attendu": "Limited / not limited",
      "Vulnérabilité attendue": "No limit on the number of failed authentication attempts with the same account",
      "Bonne pratique attendu": "The number of failed authentication attempts with the same account is limited"})
_T(59,
   Tests="Check whether the user's session depends on one or several session cookies",
   **{"Résultat attendu": "One session cookie / several session cookies",
      "Vulnérabilité attendue": "Session depending on a single session cookie",
      "Bonne pratique attendu": "Session depending on several session cookies"})
_T(60,
   Tests="Check whether the session cookies are strong (not guessable)",
   **{"Vulnérabilité attendue": "Use of non-strong session cookies",
      "Bonne pratique attendu": "Use of a strong cookie"})
_T(61,
   Tests="Check whether the cookie's \"domain\" attribute matches the full site name exactly and not just part of it",
   **{"Vulnérabilité attendue": "Cookie \"domain\" attribute misconfigured"})
_T(62,
   Tests="Check whether the \"secure\" attribute is enabled on the cookies (if the application is accessible over HTTPS)",
   **{"Résultat attendu": "Enabled / not enabled",
      "Vulnérabilité attendue": "\"Secure\" attribute not enabled on cookies",
      "Bonne pratique attendu": "\"Secure\" attribute enabled on cookies"})
_T(63,
   Tests="Check whether the \"httponly\" attribute is enabled on the cookies",
   **{"Résultat attendu": "Enabled / not enabled",
      "Vulnérabilité attendue": "\"httponly\" attribute not enabled on cookies",
      "Bonne pratique attendu": "\"httponly\" attribute enabled on cookies"})
_T(64,
   Tests="Check whether the session cookies are regenerated after authentication",
   **{"Vulnérabilité attendue": "Cookies not regenerated after authentication",
      "Bonne pratique attendu": "Cookies regenerated after authentication"})
_T(65,
   Tests="Check whether the cookies can be replayed:\n1. Open a first session with account \"1\" from a first user workstation.\n2. Open a second session with account \"2\" from a second user workstation and a different IP address.\n3. Access the data of the first session from the second session using the first session's cookies.",
   **{"Vulnérabilité attendue": "Cookies can be replayed",
      "Bonne pratique attendu": "Cookies cannot be replayed"})
_T(66,
   Tests="Check whether multi-workstation login is allowed: access the application with the same account from two different browsers at the same time",
   **{"Vulnérabilité attendue": "Multi-workstation login allowed",
      "Bonne pratique attendu": "Multi-workstation login not allowed"})
_T(67,
   Tests="Check whether session fixation is possible (this attack is meaningful if the cookie is not regenerated after authentication):\n1. The attacker, logged in on machine A, finds a way to force the legitimate user, logged in on machine B, to authenticate to the application with a \"JSESSIONID\" cookie value set by the attacker (no need to simulate this step).\n2. The legitimate user logs in to the application.\n3. The attacker creates on their own machine a \"JSESSIONID\" cookie with the same value they set for the victim and tries to access a URL that requires authentication.\n4. The attacker ends up logged in with the victim's account and shares their session as long as it is valid.",
   **{"Vulnérabilité attendue": "Session fixation possible",
      "Bonne pratique attendu": "Session fixation prevented"})
_T(68,
   Tests="Check whether the mechanism protecting against session theft is strong",
   **{"Vulnérabilité attendue": "Insufficiently strong protection against session theft"})
_T(69,
   Tests="Check whether the session's active lifetime is limited (2 hours, for example)\nCheck whether the session's idle timeout is limited (15 minutes, for example)",
   **{"Vulnérabilité attendue": "Session active lifetime deemed long\nSession idle timeout deemed long"})
_T(70,
   Tests="Analyse the responses and requests and check whether the HTTP headers follow best practices (to be developed)",
   **{"Vulnérabilité attendue": "Insecure HTTP headers"})
_T(71,
   Tests="Check whether the \"strict-transport-security\" HTTP header is enabled",
   **{"Vulnérabilité attendue": "Missing \"strict-transport-security\" HTTP header",
      "Bonne pratique attendu": "\"strict-transport-security\" HTTP header enabled"})
_T(72,
   Tests="Check whether a Content Security Policy is configured in the HTTP header of the application server's responses. (to be developed)",
   **{"Vulnérabilité attendue": "Missing Content Security Policy",
      "Bonne pratique attendu": "Content Security Policy configured"})
_T(73,
   Tests="Check whether caching is disabled: \"no-cache\" and \"no-store\" must be used.",
   **{"Vulnérabilité attendue": "Caching allowed on user workstations",
      "Bonne pratique attendu": "Caching disabled on user workstations"})
_T(74,
   Tests="Check whether the X-XSS-Protection HTTP header is enabled",
   **{"Vulnérabilité attendue": "Missing X-XSS-Protection HTTP header",
      "Bonne pratique attendu": "Use of the X-XSS-Protection HTTP header"})
_T(75,
   Tests="Check whether the application is sensitive to clickjacking",
   **{"Vulnérabilité attendue": "Application sensitive to clickjacking",
      "Bonne pratique attendu": "Application not sensitive to clickjacking"})
_T(76,
   Tests="Check whether sensitive data such as the login and password are sent via GET or POST",
   **{"Résultat attendu": "GET / POST",
      "Vulnérabilité attendue": "Sensitive data sent via GET\nPassword visible in clear text in the address bar",
      "Bonne pratique attendu": "Sensitive data sent via POST"})
_T(77,
   Tests="Test horizontal privilege escalation: check whether a user can access the session / data of another user with the same profile",
   **{"Vulnérabilité attendue": "Horizontal privilege escalation\nUser account enumeration possible",
      "Bonne pratique attendu": "Effective isolation of user sessions"})
_T(78,
   Tests="Test vertical privilege escalation: check whether a user can access features / data intended for users with a different profile",
   **{"Vulnérabilité attendue": "Vertical privilege escalation",
      "Bonne pratique attendu": "Effective management of user privileges"})
_T(79,
   Tests="Check whether the application is vulnerable to Open URL redirection",
   **{"Vulnérabilité attendue": "Application vulnerable to Open URL redirection",
      "Bonne pratique attendu": "Application not vulnerable to Open URL redirection"})
_T(80,
   Tests="Check whether the application is vulnerable to Local File Inclusion and/or Remote File Inclusion",
   Outils="fimap",
   **{"Vulnérabilité attendue": "Application vulnerable to Local File Inclusion"})
_T(81,
   Tests="Check whether logout is performed via POST (recommended) or GET",
   **{"Résultat attendu": "GET / POST",
      "Vulnérabilité attendue": "Possibility of uncontrolled user logout",
      "Bonne pratique attendu": "Logout performed via POST"})
_T(82,
   Tests="Check whether the URIs are guessable",
   **{"Vulnérabilité attendue": "Use of guessable URIs",
      "Bonne pratique attendu": "URIs not guessable"})
_T(83,
   Tests="Check whether the URIs are protected by URI obfuscation methods",
   **{"Résultat attendu": "Protected / not protected",
      "Vulnérabilité attendue": "URIs disclosing information about the services offered by the application",
      "Bonne pratique attendu": "URIs protected by obfuscation methods"})
_T(84,
   Tests="Check whether arbitrary code can be injected by manipulating the requests sent to the server (to be refined)",
   **{"Résultat attendu": "Possible / not possible",
      "Vulnérabilité attendue": "Possibility of arbitrary code injection",
      "Bonne pratique attendu": "Robust filtering of client-sent requests"})
_T(85,
   Tests="Check the robustness of the captcha: identifiable by bots / scripts, replayable, etc.",
   **{"Vulnérabilité attendue": "Captcha code replayable\nCaptcha code identifiable by bots / scripts",
      "Bonne pratique attendu": "Robust captcha code"})
_T(86,
   Tests="Check whether the \"Password\" field in the forms is masked",
   **{"Vulnérabilité attendue": "Password field not masked"})
_T(87,
   Tests="Check whether the server validates the type, size and content of uploaded files",
   Outils="fuxploider",
   **{"Vulnérabilité attendue": "Insufficient filtering of uploaded files"})
_T(88,
   Tests="Check for the presence of debug code",
   **{"Résultat attendu": "Debug code present / absent",
      "Vulnérabilité attendue": "Presence of debug code"})
_T(89,
   Tests="Check whether the application discloses specific information such as the names of a bank's customers",
   **{"Vulnérabilité attendue": "Disclosure of information about ..."})
_T(90,
   Tests="If access to the hashed passwords is obtained, check whether the hashing algorithm is strong or not",
   **{"Vulnérabilité attendue": "Use of a weak hashing algorithm",
      "Bonne pratique attendu": "Use of a strong hashing algorithm"})
_T(91,
   Tests="Check whether the SID is guessable",
   **{"Réf. Procédure": "SID, server ID, any type of ID — same checks as for IDOR",
      "Commentaires": "What is a SID?",
      "Vulnérabilité attendue": "Use of a guessable SID"})
_T(92,
   Tests="Check whether the email addresses written on the website are well protected against harvesting by bots",
   **{"Réf. Procédure": "In the JS files, HTML, etc. — there are some tools for this",
      "Commentaires": "How to do it / which tools?",
      "Vulnérabilité attendue": "Email address not sufficiently protected against automatic harvesting by bots"})
_T(93,
   Tests="Is Local File Inclusion allowed?",
   **{"Réf. Procédure": "LFI, LFD, directory listing, etc.",
      "Commentaires": "More details",
      "Vulnérabilité attendue": "Is Local File Inclusion allowed?"})
_T(94,
   Tests="Test username enumeration",
   **{"Résultat attendu": "Enumeration possible / not possible",
      "Vulnérabilité attendue": "User account enumeration",
      "Bonne pratique attendu": "The application is not sensitive to user account enumeration"})
_T(95,
   Tests="Test the password reset logic")
_T(96,
   Tests="Test password reset poisoning",
   **{"Résultat attendu": "Sensitive / not sensitive",
      "Vulnérabilité attendue": "Password reset poisoning possible",
      "Bonne pratique attendu": "The application is not vulnerable to password reset poisoning"})
_T(97,
   Tests="Test the 2FA logic",
   **{"Vulnérabilité attendue": "2FA logic vulnerable",
      "Bonne pratique attendu": "2FA logic not vulnerable"})
_T(98,
   Tests="Test the different authentication stages when multi-stage authentication is used",
   **{"Vulnérabilité attendue": "One of the authentication stages is vulnerable",
      "Bonne pratique attendu": "The multi-stage authentication is not vulnerable"})
_T(99,
   Tests="Check whether password confirmation is missing when changing email, password or 2FA (CSRF vector)",
   **{"Résultat attendu": "No email confirmation / email confirmation required",
      "Vulnérabilité attendue": "No email confirmation when changing a setting",
      "Bonne pratique attendu": "Email confirmation required when changing a setting"})
_T(100,
   Tests="Test authentication via OAuth for Open Redirection",
   **{"Résultat attendu": "Sensitive / not sensitive",
      "Vulnérabilité attendue": "OAuth authentication sensitive to Open Redirection",
      "Bonne pratique attendu": "OAuth authentication protected against Open Redirection"})
_T(101,
   Tests="If the application uses JWT, test the common flaws",
   Outils="jwt_tool\njwt2john",
   **{"Résultat attendu": "JWT vulnerable / JWT not vulnerable",
      "Vulnérabilité attendue": "JWT implementation is vulnerable",
      "Bonne pratique attendu": "Sound JWT implementation"})
_T(102,
   Tests="Test a brute-force attack against the OTP",
   **{"Vulnérabilité attendue": "No limit on the number of failed authentication attempts with the OTP",
      "Bonne pratique attendu": "The number of failed authentication attempts with the OTP is limited"})
_T(103,
   Tests="Check whether the application uses serialized objects controlled by the user",
   Outils="Burp Suite (detection)\nysoserial (exploitation)",
   **{"Vulnérabilité attendue": "Serialized object exploitable",
      "Bonne pratique attendu": "Serialized object not exploitable"})
_T(104,
   Tests="Test IDOR attacks",
   **{"Résultat attendu": "Sensitive / not sensitive",
      "Vulnérabilité attendue": "Application vulnerable to IDOR attacks",
      "Bonne pratique attendu": "The application handles access controls correctly"})
_T(105,
   Tests="Modify the cookies to generate errors")
_T(106,
   Tests="Try parameter pollution by adding two values for the same parameter")
_T(107,
   Tests="Check whether the cookies change when using the \"remember me\" feature")

# ──────── Tests pré-auth à faire en post-auth (108–117): formula refs ─────────
# These rows reference other rows via spreadsheet formulas (=C15, =I19, …). The
# formula strings are left intact — they are not human prose to translate.

# ─────────────────────────── Business logic (118–127) ────────────────────────
_T(118,
   Tests="Try to manipulate the product ID, price or quantity value in any action (add, edit, delete, place, pay, etc.)",
   Outils="Burp Suite",
   **{"Résultat attendu": "Parameters controlled / no control",
      "Vulnérabilité attendue": "No control over sensitive parameters"})
_T(119,
   Tests="Try parameter pollution to use the same coupon twice in the same request",
   **{"Résultat attendu": "Coupon reuse possible / not possible",
      "Vulnérabilité attendue": "No control over the number of uses of a coupon"})
_T(120,
   Tests="Test the multi-stage purchase flow",
   **{"Résultat attendu": "Flow vulnerable / not vulnerable"})
_T(121,
   Tests="Try to reuse the same coupon several times",
   **{"Résultat attendu": "Coupon reuse possible / not possible"})
_T(122,
   Tests="Check whether the coupons are predictable",
   **{"Résultat attendu": "Coupons predictable / not predictable"})
_T(123,
   Tests="Check the transaction logic",
   **{"Résultat attendu": "Transaction logic vulnerable / not vulnerable"})
_T(124,
   Tests="Change sensitive POST requests to GET",
   **{"Résultat attendu": "Sending via GET possible / not possible"})
_T(125,
   Tests="Test IDOR on other users' sensitive data",
   **{"Résultat attendu": "Sensitive / not sensitive"})
_T(126,
   Tests="Check PDF generation for IDOR",
   **{"Résultat attendu": "Sensitive / not sensitive"})
_T(127,
   Tests="Test the race condition attack on payment",
   Outils="race-the-web",
   **{"Résultat attendu": "Sensitive / not sensitive"})


# ── Feuil1 sheet (reference matrix) ──────────────────────────────────────────
FEUIL1 = {
    # section name → English
    "sections": {
        "Information Gathering": "Information Gathering",
        "Test de gestion de la configuration et du déploiement":
            "Configuration and Deployment Management Testing",
        "Not Started": "Not Started",
        "Pass": "Pass",
        "Issues": "Issues",
        "N/A": "N/A",
        "In progress": "In progress",
    },
    # test ID (within Feuil1) → translated fields
    "tests": {
        "1": {"Etapes": "Server discovery",
              "Description": "Gather information about the server\nCollect Whois information",
              "Outils": "OSINT, WhoisLookup, DNS lookup (dnsstuff.com, …), Nmap, …"},
        "2": {"Etapes": "Service discovery",
              "Description": "Scan for common ports.\nCheck whether the enabled services are insecure / dangerous / unnecessary\nCheck whether the platform's administration services are reachable from the \"Users\" network / the Internet",
              "Outils": "nmap, netscan"},
        "3": {"Etapes": "Server identification (banner grabbing)",
              "Description": "Analyse the header fields of the server's responses to identify the brand, model and version",
              "Outils": "telnet, Burp Suite"},
        "4": {"Etapes": "Detection / identification of network components (proxy, WAF, routers, …)",
              "Description": "Detection / identification of network components (proxy, WAF, routers, …)",
              "Outils": "traceroute, nmap, HTTP TRACE method, WAFW00F, WhatWaf"},
        "5": {"Etapes": "Discovery of hidden content",
              "Description": "Discover hidden content and features that are not visible: check for the presence of /robots.txt /crossdomain.xml /clientaccesspolicy.xml /phpinfo.php /sitemap.xml and /.well-known/\n/.git",
              "Outils": "web crawler, attacker-directed spidering, Burp Suite"},
        "6": {"Etapes": "Identify server-side technologies",
              "Description": "Identify the operating systems, applications, technologies, library versions, etc. in use\nPerform detailed server fingerprinting; analyse the HTTP headers and HTML source to identify server-side technologies.\nExamine the URLs for file extensions and other identifying information.\nExamine the error-page messages.\nExamine the session tokens.\n\"httprint\"",
              "Outils": "nmap, Burp Suite"},
        "7": {"Etapes": "Identify entry points for user input",
              "Description": "Examine the URL, HTTP header, query-string parameters, POST data and cookies\nIdentify the HTTP header parameters that the application may treat as user input, such as the User-Agent, Referer, Accept, Accept-Language and Host headers\nDetermine the URL-encoding techniques and the other encryption measures used to secure web traffic, such as SSL",
              "Outils": "Burp Suite, HttPrint, WebScarab, Zaproxy"},
        "8": {"Etapes": "Map the attack surface",
              "Description": "Identify the various attack surfaces exposed by the applications and the vulnerabilities associated with each, and generate a map based on the research carried out.",
              "Outils": "shodan.io, Sifter, crt.sh, search.censys.io, …"},
    },
    # Status values seen in Feuil1
    "status": {"Pass": "Pass"},
}


def translate_value(key, value):
    """Translate one field value. Returns (new_value, was_translated_or_frozen)."""
    if value is None or key in _FROZEN_KEYS:
        return value, True
    if not isinstance(value, str):
        return value, True
    if value in BOILERPLATE:
        return BOILERPLATE[value], True
    return value, False  # untranslated — caller decides


def main():
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    untranslated = []

    # ── Pentest Web ──
    for block in data.get("Pentest Web", []):
        for test in block.get("tests", []):
            tid = str(test.get("ID", ""))
            per_test = TRANSLATIONS.get(tid, {})
            for key in list(test.keys()):
                val = test[key]
                # 1) per-test explicit translation wins
                if key in per_test:
                    test[key] = per_test[key]
                    continue
                # 2) boilerplate / frozen
                new_val, handled = translate_value(key, val)
                test[key] = new_val
                if not handled:
                    untranslated.append((tid, key, val))

    # ── Feuil1 ──
    for block in data.get("Feuil1", []):
        sec = block.get("section")
        if sec in FEUIL1["sections"]:
            block["section"] = FEUIL1["sections"][sec]
        for test in block.get("tests", []):
            tid = str(test.get("ID", ""))
            per = FEUIL1["tests"].get(tid, {})
            for key in list(test.keys()):
                if key in per:
                    test[key] = per[key]
                elif key == "Status" and test[key] in FEUIL1["status"]:
                    test[key] = FEUIL1["status"][test[key]]

    JSON_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(f"Wrote {JSON_PATH}")
    if untranslated:
        print(f"\n[!] {len(untranslated)} value(s) left untranslated (not boilerplate, "
              f"no per-test entry) - review these:")
        for tid, key, val in untranslated:
            v = (val[:70] + "…") if len(val) > 70 else val
            print(f"  [ID {tid}] {key}: {v!r}")
    else:
        print("All non-null values were translated or explicitly frozen.")


if __name__ == "__main__":
    main()
