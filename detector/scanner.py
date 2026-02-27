import re
from urllib.parse import urlparse
class PhishingScanner:
    def __init__(self):
        self.trusted_brands=["google","amazon","paypal","apple","microsoft"]
    def has_ip_address(self,domain):
        ip_pattern=re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        return bool(ip_pattern.match(domain))
    def is_typosquatting(self,domain):
        for brand in self.trusted_brands:
            if brand in domain and domain != f"{brand}.com":
                return True
        return False
    def scan_url(self,url):
        if not url.startswith("http"):
            url="http://"+url
        parsed_url=urlparse(url)
        domain=parsed_url.netloc.lower()
        issues=[]
        for brand in self.trusted_brands:
            if brand in domain:
                is_official=(domain==f"brand.com") or (domain==f"www.{brand}.com")
                if not is_official:
                    issues.append(f"Red Flag: Suspicious use of trusted brand or mimic a trusted brand(Typosquatting).'{brand.capitalize()}'.")
        # if self.has_ip_address(domain):
        #     issues.append("Red Flag:Uses an IP address instead of a domain name.")
        # if self.is_typosquatting(domain):
        #     issues.append("Red Flag:Looks like it's trying to mimic a trusted brand(Typosquatting).")
        ip_pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.search(ip_pattern,domain):
            issues.append("Red Flag:Uses a raw IP address instead of a domain name.")
        if len(url)>75:
            issues.append("Warning;URL is suspiciously long.")
        if "-" in domain:
            issues.append("Warning:Domain contains hyphens(very common in phishing links).")
        return issues