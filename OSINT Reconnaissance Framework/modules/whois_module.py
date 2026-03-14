import socket
import ssl
import re
from datetime import datetime

class WhoisLookup:
    def __init__(self):
        self.data = {}
        # Common WHOIS servers for TLDs
        self.whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'io': 'whois.nic.io',
            'co': 'whois.nic.co',
            'info': 'whois.afilias.net',
            'biz': 'whois.biz',
            'us': 'whois.nic.us',
            'uk': 'whois.nic.uk',
            'de': 'whois.denic.de',
            'fr': 'whois.nic.fr',
            'jp': 'whois.jprs.jp',
            'au': 'whois.auda.org.au',
            'ca': 'whois.cira.ca',
        }
    
    def get_info(self, domain):
        # Try python-whois first, fallback to direct socket query
        try:
            return self._try_python_whois(domain)
        except Exception as e:
            print(f"Python-whois failed: {e}, trying direct query...")
            try:
                return self._direct_whois_query(domain)
            except Exception as e2:
                return {
                    'error': f'WHOIS lookup failed: {str(e2)}',
                    'domain_name': domain,
                    'registrar': 'Lookup Failed',
                    'creation_date': 'N/A',
                    'expiration_date': 'N/A',
                    'name_servers': [],
                    'emails': []
                }
    
    def _try_python_whois(self, domain):
        """Try using python-whois library"""
        import whois
        w = whois.whois(domain)
        
        # Handle different response types (string vs list)
        domain_name = w.domain_name
        if isinstance(domain_name, list):
            domain_name = domain_name[0]
        
        creation_date = self._format_date(w.creation_date)
        expiration_date = self._format_date(w.expiration_date)
        updated_date = self._format_date(w.updated_date)
        
        # Handle name servers
        name_servers = w.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif not isinstance(name_servers, list):
            name_servers = []
        
        # Clean up name servers (lowercase and strip)
        name_servers = [ns.lower().strip() for ns in name_servers if ns]
        
        # Handle emails
        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]
        elif not isinstance(emails, list):
            emails = []
        
        return {
            'domain_name': domain_name or domain,
            'registrar': w.registrar or 'N/A',
            'creation_date': creation_date,
            'expiration_date': expiration_date,
            'updated_date': updated_date,
            'name_servers': name_servers,
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            'emails': emails,
            'org': w.org or w.registrant_organization or 'N/A',
            'country': w.country or w.registrant_country or 'N/A',
            'dnssec': w.dnssec or 'N/A',
            'source': 'python-whois'
        }
    
    def _direct_whois_query(self, domain):
        """Fallback: Direct WHOIS query using socket"""
        # Extract TLD
        parts = domain.lower().split('.')
        if len(parts) < 2:
            raise ValueError("Invalid domain format")
        
        tld = parts[-1]
        whois_server = self.whois_servers.get(tld, f'whois.nic.{tld}')
        
        # Query the WHOIS server
        result = self._query_whois_server(domain, whois_server)
        
        # Parse the result
        parsed = self._parse_whois_text(result, domain)
        parsed['source'] = 'direct-query'
        return parsed
    
    def _query_whois_server(self, domain, server, port=43):
        """Send WHOIS query via socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            sock.connect((server, port))
            query = f"{domain}\r\n"
            sock.send(query.encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            return response.decode('utf-8', errors='ignore')
        finally:
            sock.close()
    
    def _parse_whois_text(self, text, domain):
        """Parse WHOIS text response"""
        data = {
            'domain_name': domain,
            'registrar': 'N/A',
            'creation_date': 'N/A',
            'expiration_date': 'N/A',
            'updated_date': 'N/A',
            'name_servers': [],
            'status': [],
            'emails': [],
            'org': 'N/A',
            'country': 'N/A',
            'dnssec': 'N/A'
        }
        
        # Common patterns for WHOIS fields
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'(Creation Date|created|Created On):\s*(.+)',
            'expiration_date': r'(Expiration Date|Registry Expiry Date|expires|Expiration):\s*(.+)',
            'updated_date': r'(Updated Date|Updated On|last-update|modified):\s*(.+)',
            'org': r'(Registrant Organization|Organization|org|Organisation):\s*(.+)',
            'country': r'(Registrant Country|Country|country):\s*(.+)',
            'dnssec': r'DNSSEC:\s*(.+)'
        }
        
        # Extract simple fields
        for field, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                value = match.group(2) if len(match.groups()) > 1 else match.group(1)
                data[field] = value.strip()
        
        # Extract name servers (multiple possible formats)
        ns_patterns = [
            r'Name Server:\s*(.+)',
            r'NameServer:\s*(.+)',
            r'nserver:\s*(.+)',
            r'Nameserver:\s*(.+)'
        ]
        
        for pattern in ns_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                ns = match.strip().lower()
                if ns and ns not in data['name_servers']:
                    data['name_servers'].append(ns)
        
        # Extract emails
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        emails = re.findall(email_pattern, text)
        data['emails'] = list(set(emails))  # Remove duplicates
        
        # Clean up dates
        data['creation_date'] = self._clean_date(data['creation_date'])
        data['expiration_date'] = self._clean_date(data['expiration_date'])
        data['updated_date'] = self._clean_date(data['updated_date'])
        
        return data
    
    def _clean_date(self, date_str):
        """Clean up date string"""
        if not date_str or date_str == 'N/A':
            return 'N/A'
        
        # Remove extra text after date
        date_str = date_str.split('T')[0]  # Remove time part
        date_str = re.sub(r'\s+.*$', '', date_str)  # Remove everything after space
        
        return date_str
    
    def _format_date(self, date):
        """Format date from various types"""
        if date is None:
            return 'N/A'
        if isinstance(date, list):
            date = date[0]
        if isinstance(date, datetime):
            return date.strftime('%Y-%m-%d')
        if isinstance(date, str):
            return date.split('T')[0]
        return str(date)