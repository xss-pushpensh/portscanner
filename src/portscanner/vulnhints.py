"""Small local vulnerability hint engine.

This is NOT a full vulnerability scanner. It maps known dangerous
version strings to short human-readable advisories.
"""
import re
from typing import List


VULN_DB = [
    (re.compile(r"Apache/2\.4\.49", re.IGNORECASE),
     ["CVE-2021-41773 — Apache 2.4.49 path traversal and RCE",
      "Recommendation: upgrade to Apache 2.4.51+"]),
    (re.compile(r"Apache/2\.4\.50", re.IGNORECASE),
     ["CVE-2021-42013 — Apache 2.4.50 path traversal and RCE",
      "Recommendation: upgrade to Apache 2.4.51+"]),
    (re.compile(r"OpenSSH[_ ]?(?:[1-6]\.|7\.[0-3])", re.IGNORECASE),
     ["OpenSSH < 7.4 — CVE-2016-0777 roaming client key leak",
      "Recommendation: upgrade OpenSSH to 7.4+"]),
    (re.compile(r"vsFTPd[\s_ ]?2\.3\.4", re.IGNORECASE),
     ["CVE-2011-2523 — vsFTPd 2.3.4 backdoor",
      "Recommendation: upgrade vsFTPd immediately"]),
    (re.compile(r"nginx/(?:1\.20\.0|1\.21\.0)", re.IGNORECASE),
     ["CVE-2021-23017 — nginx resolver off-by-one",
      "Recommendation: upgrade nginx to 1.21.1 or 1.20.1"]),
    (re.compile(r"ProFTPD[\s_ ]?1\.3\.3", re.IGNORECASE),
     ["CVE-2010-4221 — ProFTPD 1.3.3c backdoor",
      "Recommendation: upgrade ProFTPD"]),
    (re.compile(r"Microsoft-IIS/(?:[1-6]\.)", re.IGNORECASE),
     ["Legacy IIS version — multiple historical RCEs",
      "Recommendation: upgrade to a supported IIS release"]),
]


def get_vuln_hints(service: str, version: str, banner: str) -> List[str]:
    """Return a list of hint strings matching this service/version/banner."""
    haystack = " ".join(filter(None, [service, version, banner]))
    hints: List[str] = []
    for pattern, messages in VULN_DB:
        if pattern.search(haystack):
            hints.extend(messages)
    return hints
