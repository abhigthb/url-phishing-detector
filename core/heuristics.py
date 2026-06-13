import re
import requests
import whois
import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher
from dataclasses import dataclass
from cachetools import TTLCache, cached

# Caches for network calls
redirect_cache = TTLCache(maxsize=1000, ttl=600)  # 10 minutes
whois_cache = TTLCache(maxsize=1000, ttl=3600)    # 1 hour

@dataclass
class HeuristicResult:
    triggered: bool
    score_contribution: int
    evidence: str
    extra_data: dict = None

class BaseHeuristic:
    name: str = "Base"
    description: str = ""
    weight: int = 1

    def check(self, url: str) -> HeuristicResult:
        raise NotImplementedError

HEURISTICS_REGISTRY = []

def register(cls):
    HEURISTICS_REGISTRY.append(cls())
    return cls

# --- ORIGINAL HEURISTICS (1-10) Refactored ---

@register
class LengthHeuristic(BaseHeuristic):
    name = "URL Length"
    weight = 2
    def check(self, url):
        triggered = len(url) > 100
        return HeuristicResult(triggered, self.weight if triggered else 0, "Unusually long URL (obfuscation risk).")

@register
class IPAddressHeuristic(BaseHeuristic):
    name = "IP Hostname"
    weight = 3
    def check(self, url):
        hostname = urlparse(url).hostname or ''
        triggered = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))
        return HeuristicResult(triggered, self.weight if triggered else 0, "Uses raw IP address instead of domain.")

@register
class AtSymbolHeuristic(BaseHeuristic):
    name = "@ Symbol Obfuscation"
    weight = 3
    def check(self, url):
        triggered = '@' in url
        return HeuristicResult(triggered, self.weight if triggered else 0, "Contains '@' symbol (credential phishing).")

@register
class ExcessiveSubdomainsHeuristic(BaseHeuristic):
    name = "Excessive Subdomains"
    weight = 2
    def check(self, url):
        hostname = urlparse(url).hostname or ''
        parts = hostname.split('.')
        triggered = len([p for p in parts[:-2] if p]) > 3
        return HeuristicResult(triggered, self.weight if triggered else 0, "More than 3 subdomains detected.")

@register
class SuspiciousTLDHeuristic(BaseHeuristic):
    name = "Suspicious TLD"
    weight = 2
    def check(self, url):
        hostname = urlparse(url).hostname or ''
        tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.icu']
        triggered = any(hostname.lower().endswith(tld) for tld in tlds)
        return HeuristicResult(triggered, self.weight if triggered else 0, "Uses a high-risk Top Level Domain.")

@register
class HTTPHeuristic(BaseHeuristic):
    name = "Insecure Protocol"
    weight = 1
    def check(self, url):
        triggered = urlparse(url).scheme != 'https' and not url.startswith('data:')
        return HeuristicResult(triggered, self.weight if triggered else 0, "Not using secure HTTPS protocol.")

@register
class TyposquattingHeuristic(BaseHeuristic):
    name = "Typosquatting"
    weight = 3
    brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix', 'chase']
    def check(self, url):
        hostname = urlparse(url).hostname or ''
        parts = hostname.split('.')
        domain = parts[-2] if len(parts) > 1 else hostname
        for brand in self.brands:
            sim = SequenceMatcher(None, domain.lower(), brand).ratio()
            if 0.82 < sim < 1.0:
                return HeuristicResult(True, self.weight, f"Similar to '{brand}' ({sim:.2f} match).")
        return HeuristicResult(False, 0, "")

@register
class SuspiciousKeywordsHeuristic(BaseHeuristic):
    name = "Suspicious Keywords"
    weight = 1
    keywords = ['login', 'verify', 'secure', 'billing', 'update', 'password', 'support']
    def check(self, url):
        triggered = any(kw in url.lower() for kw in self.keywords)
        return HeuristicResult(triggered, self.weight if triggered else 0, "Contains high-risk keywords in path/query.")

@register
class ExcessiveHyphensHeuristic(BaseHeuristic):
    name = "Excessive Hyphens"
    weight = 1
    def check(self, url):
        hostname = urlparse(url).hostname or ''
        triggered = hostname.count('-') > 4
        return HeuristicResult(triggered, self.weight if triggered else 0, "Excessive hyphens in domain.")

@register
class DoubleSlashHeuristic(BaseHeuristic):
    name = "Double Slash Obfuscation"
    weight = 2
    def check(self, url):
        path = urlparse(url).path
        triggered = '//' in path
        return HeuristicResult(triggered, self.weight if triggered else 0, "Suspicious '//' found in URL path.")

# --- NEW V1 HEURISTICS (11-16) ---

@register
class PunycodeHomographHeuristic(BaseHeuristic):
    name = "IDN Homograph (Punycode)"
    weight = 4
    def check(self, url):
        hostname = urlparse(url).hostname or ''
        if 'xn--' in hostname.lower():
            return HeuristicResult(True, self.weight, "Punycode (xn--) detected. Potential homograph attack.")
        return HeuristicResult(False, 0, "")

@register
class RedirectChainHeuristic(BaseHeuristic):
    name = "Redirect Chain"
    weight = 2
    @cached(redirect_cache)
    def fetch_chain(self, url):
        try:
            res = requests.get(url, timeout=3, allow_redirects=True)
            chain = [r.url for r in res.history] + [res.url]
            return chain
        except requests.RequestException:
            return []

    def check(self, url):
        # Skip for data URIs
        if url.startswith('data:'): return HeuristicResult(False, 0, "")
        chain = self.fetch_chain(url)
        if not chain:
            return HeuristicResult(False, 0, "Could not verify redirects (connection error).")
        
        orig_domain = urlparse(url).hostname
        final_domain = urlparse(chain[-1]).hostname
        triggered = orig_domain != final_domain and len(chain) > 1
        
        return HeuristicResult(
            triggered, self.weight if triggered else 0, 
            f"Redirects to different domain: {final_domain}",
            extra_data={"chain": chain}
        )

@register
class NewlyRegisteredDomainHeuristic(BaseHeuristic):
    name = "Newly Registered Domain"
    weight = 2
    @cached(whois_cache)
    def get_whois_date(self, domain):
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            return creation_date
        except:
            return None

    def check(self, url):
        hostname = urlparse(url).hostname or ''
        date = self.get_whois_date(hostname)
        if date and isinstance(date, datetime.datetime):
            age_days = (datetime.datetime.now() - date).days
            if age_days < 30:
                return HeuristicResult(True, self.weight, f"Domain is less than 30 days old ({age_days} days).")
        return HeuristicResult(False, 0, "")

@register
class LookalikeCharHeuristic(BaseHeuristic):
    name = "Lookalike Character Substitution"
    weight = 3
    subs = {'0': 'o', '1': 'l', 'rn': 'm', 'vv': 'w', 'cl': 'd'}
    brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix', 'chase']
    
    def check(self, url):
        hostname = urlparse(url).hostname or ''
        parts = hostname.split('.')
        domain = parts[-2] if len(parts) > 1 else hostname
        
        test_domain = domain.lower()
        for k, v in self.subs.items():
            test_domain = test_domain.replace(k, v)
            
        if test_domain != domain.lower() and test_domain in self.brands:
            return HeuristicResult(True, self.weight, f"Lookalike chars mask target brand: '{test_domain}'.")
        return HeuristicResult(False, 0, "")

@register
class ExcessivePathDepthHeuristic(BaseHeuristic):
    name = "Excessive Path Depth"
    weight = 1
    def check(self, url):
        path_segments = [seg for seg in urlparse(url).path.split('/') if seg]
        triggered = len(path_segments) > 6
        return HeuristicResult(triggered, self.weight if triggered else 0, f"Path has {len(path_segments)} segments (legit URLs rarely have > 6).")

@register
class DataURIHeuristic(BaseHeuristic):
    name = "Data URI Payload (Bonus)"
    weight = 4
    def check(self, url):
        triggered = url.lower().startswith('data:')
        return HeuristicResult(triggered, self.weight if triggered else 0, "Uses Data URI scheme to bypass domain checks.")

def analyze_url(url):
    results = []
    total_score = 0
    redirect_chain = []
    
    for heuristic in HEURISTICS_REGISTRY:
        res = heuristic.check(url)
        results.append({
            "name": heuristic.name,
            "description": heuristic.description,
            "triggered": res.triggered,
            "score": res.score_contribution,
            "evidence": res.evidence
        })
        total_score += res.score_contribution
        if res.extra_data and "chain" in res.extra_data:
            redirect_chain = res.extra_data["chain"]
            
    return results, total_score, redirect_chain