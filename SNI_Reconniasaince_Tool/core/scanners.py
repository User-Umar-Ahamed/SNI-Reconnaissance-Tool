import socket
import ssl
import time
import subprocess
import re
import os
from typing import List, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

PORT = 443
TIMEOUT = 3  # Increased from 0.6 to 3 seconds
MAX_WORKERS = 20
MAX_TOTAL_TARGETS = 60


@dataclass
class ScanResult:
    """Scan result data"""
    domain: str
    port: int
    latency: Optional[float]
    status: str  # "Valid SNI" or "Blocked"


class BaseScanner:
    """Base scanner class"""
    
    def __init__(self):
        self.port = PORT
        self.timeout = TIMEOUT
        self.max_workers = MAX_WORKERS
        self.max_targets = MAX_TOTAL_TARGETS
    
    def get_domains(self) -> List[str]:
        raise NotImplementedError
    
    def test_domain(self, domain: str) -> ScanResult:
        """Test if domain works as SNI - lenient approach"""
        start_time = time.time()
        
        # Step 1: Check DNS resolution
        try:
            resolved_ip = socket.gethostbyname(domain)
            
            # Check for obvious block IPs
            blocked_ips = ['0.0.0.0', '127.0.0.1']
            
            if resolved_ip in blocked_ips:
                return ScanResult(
                    domain=domain,
                    port=self.port,
                    latency=None,
                    status="Blocked"
                )
            
            # Check for private IP ranges (definite block)
            ip_parts = resolved_ip.split('.')
            if (ip_parts[0] == '10' or 
                (ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31) or
                (ip_parts[0] == '192' and ip_parts[1] == '168')):
                return ScanResult(
                    domain=domain,
                    port=self.port,
                    latency=None,
                    status="Blocked"
                )
                
        except socket.gaierror:
            # DNS resolution failed - definitely blocked
            return ScanResult(
                domain=domain,
                port=self.port,
                latency=None,
                status="Blocked"
            )
        except Exception:
            return ScanResult(
                domain=domain,
                port=self.port,
                latency=None,
                status="Blocked"
            )
        
        # Step 2: Try TLS handshake - first without cert verification
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try without certificate verification first
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=domain)
            ssl_sock.connect((resolved_ip, self.port))
            
            latency = (time.time() - start_time) * 1000
            
            # Connection successful - now check if it's a block page
            # Get certificate to verify
            try:
                cert = ssl_sock.getpeercert()
                
                # If we can get peer cert, check if it matches
                # But only mark as blocked if it's OBVIOUSLY wrong
                if cert:
                    cert_domains = []
                    
                    # Get all domains from certificate
                    for san in cert.get('subjectAltName', []):
                        if san[0] == 'DNS':
                            cert_domains.append(san[1].lower())
                    
                    for subject in cert.get('subject', []):
                        for key, value in subject:
                            if key == 'commonName':
                                cert_domains.append(value.lower())
                    
                    # Check if domain matches ANY cert domain (including wildcards)
                    domain_matches = False
                    for cert_domain in cert_domains:
                        if cert_domain == domain.lower():
                            domain_matches = True
                            break
                        # Check wildcard
                        if cert_domain.startswith('*.'):
                            if domain.lower().endswith(cert_domain[1:]):
                                domain_matches = True
                                break
                        # Check if cert domain is parent domain
                        if domain.lower().endswith('.' + cert_domain):
                            domain_matches = True
                            break
                    
                    # Only mark as blocked if certificate is OBVIOUSLY a block page
                    # (pfsense, block, localhost, etc.)
                    if not domain_matches:
                        block_page_indicators = [
                            'block', 'denied', 'filtered', 'firewall', 
                            'dnsbl', 'adblock', 'localhost', 'redirect',
                            'captive', 'portal'
                        ]
                        for indicator in block_page_indicators:
                            for cert_domain in cert_domains:
                                if indicator in cert_domain.lower():
                                    ssl_sock.close()
                                    return ScanResult(
                                        domain=domain,
                                        port=self.port,
                                        latency=None,
                                        status="Blocked"
                                    )
                        
                        # Certificate doesn't match but not an obvious block page
                        # Mark as Valid SNI anyway (might be CDN, redirect, etc.)
                        
            except:
                # Can't get certificate info - that's okay
                pass
            
            ssl_sock.close()
            
            # TLS connection worked - mark as Valid SNI
            return ScanResult(
                domain=domain,
                port=self.port,
                latency=latency,
                status="Valid SNI"
            )
            
        except ssl.SSLError:
            # SSL error - might be blocked or just SSL issue
            # Try to determine if it's a block page
            return ScanResult(
                domain=domain,
                port=self.port,
                latency=None,
                status="Blocked"
            )
        except socket.timeout:
            # Timeout - mark as blocked
            return ScanResult(
                domain=domain,
                port=self.port,
                latency=None,
                status="Blocked"
            )
        except Exception:
            # Connection failed - blocked
            return ScanResult(
                domain=domain,
                port=self.port,
                latency=None,
                status="Blocked"
            )
    
    def scan(self, progress_callback: Optional[Callable] = None) -> List[ScanResult]:
        domains = self.get_domains()
        
        if len(domains) > self.max_targets:
            domains = domains[:self.max_targets]
        
        results = []
        completed = 0
        total = len(domains)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(self.test_domain, domain): domain
                for domain in domains
            }
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    if progress_callback:
                        progress_callback(completed, total, domain, result)
                        
                except Exception:
                    result = ScanResult(domain=domain, port=self.port, latency=None, status="Blocked")
                    results.append(result)
                    completed += 1
                    
                    if progress_callback:
                        progress_callback(completed, total, domain, result)
        
        return results


class DNSCacheScanner(BaseScanner):
    """Extract domains from DNS cache"""
    
    def get_domains(self) -> List[str]:
        domains = set()
        
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if "Record Name" in line or "record name" in line.lower():
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            domain = parts[1].strip().rstrip('.')
                            if self._is_valid_domain(domain):
                                domains.add(domain)
        except:
            pass
        
        return list(domains)
    
    def _is_valid_domain(self, domain: str) -> bool:
        if not domain or len(domain) > 253:
            return False
        
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if re.match(pattern, domain):
            if domain.lower() in ['localhost', 'localhost.localdomain']:
                return False
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                return False
            return True
        
        return False


class CommonSitesScanner(BaseScanner):
    """Scan common sites from file"""
    
    def __init__(self, sites_file: str = "data/common_sites.txt"):
        super().__init__()
        self.sites_file = sites_file
    
    def get_domains(self) -> List[str]:
        domains = []
        
        # Check if file exists
        if not os.path.exists(self.sites_file):
            raise FileNotFoundError(
                f"Sites file not found: {self.sites_file}\n"
                f"Please ensure data/common_sites.txt exists in the tool directory."
            )
        
        try:
            with open(self.sites_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip()
                    # Skip empty lines and comments
                    if domain and not domain.startswith('#'):
                        # Clean domain (remove http://, https://, paths)
                        domain = domain.replace('https://', '').replace('http://', '')
                        domain = domain.split('/')[0].split('?')[0].split(':')[0]
                        if domain:
                            domains.append(domain)
        except Exception as e:
            raise Exception(f"Error reading sites file: {e}")
        
        return domains


class CustomDomainScanner(BaseScanner):
    """Scan custom domains"""
    
    def __init__(self, domains: List[str]):
        super().__init__()
        self.domains = self._clean_domains(domains)
    
    def get_domains(self) -> List[str]:
        return self.domains
    
    def _clean_domains(self, domains: List[str]) -> List[str]:
        cleaned = []
        
        for domain in domains:
            domain = domain.strip()
            if not domain:
                continue
            
            domain = domain.replace('https://', '').replace('http://', '')
            domain = domain.split('/')[0].split('?')[0].split(':')[0]
            
            if domain and '.' in domain:
                cleaned.append(domain)
        
        seen = set()
        unique = []
        for domain in cleaned:
            if domain.lower() not in seen:
                seen.add(domain.lower())
                unique.append(domain)
        
        return unique
