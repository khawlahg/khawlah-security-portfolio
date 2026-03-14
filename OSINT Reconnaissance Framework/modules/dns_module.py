import dns.resolver
import dns.zone
import socket

class DNSRecon:
    def __init__(self):
        self.records = {}
    
    def get_records(self, domain):
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        self.records = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'soa_record': {},
            'subdomains': []
        }
        
        # Get A Records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                self.records['a_records'].append({
                    'ip': str(rdata),
                    'reverse_dns': self._reverse_dns(str(rdata))
                })
        except Exception:
            pass
        
        # Get MX Records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                self.records['mx_records'].append({
                    'preference': rdata.preference,
                    'exchange': str(rdata.exchange)
                })
        except Exception:
            pass
        
        # Get NS Records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                self.records['ns_records'].append(str(rdata))
        except Exception:
            pass
        
        # Get TXT Records
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                self.records['txt_records'].append(str(rdata))
        except Exception:
            pass
        
        # Get SOA Record
        try:
            answers = dns.resolver.resolve(domain, 'SOA')
            for rdata in answers:
                self.records['soa_record'] = {
                    'mname': str(rdata.mname),
                    'rname': str(rdata.rname),
                    'serial': rdata.serial,
                    'refresh': rdata.refresh,
                    'retry': rdata.retry,
                    'expire': rdata.expire,
                    'minimum': rdata.minimum
                }
        except Exception:
            pass
        
        # Common subdomain enumeration
        common_subs = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 'test', 'portal']
        for sub in common_subs:
            try:
                subdomain = f"{sub}.{domain}"
                answers = dns.resolver.resolve(subdomain, 'A')
                for rdata in answers:
                    self.records['subdomains'].append({
                        'name': subdomain,
                        'ip': str(rdata)
                    })
            except Exception:
                continue
        
        return self.records
    
    def _reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return 'No reverse DNS'