import requests
import hashlib

class BreachChecker:
    def __init__(self):
        # Using HaveIBeenPwned API (requires key for production)
        # For demo, we'll use a mock/simulated approach or public alternatives
        self.hibp_url = "https://haveibeenpwned.com/api/v3"
        self.headers = {
            'User-Agent': 'OSINT-Framework-Student-Project'
        }
    
    def check_domain(self, domain):
        results = {
            'breached_accounts': [],
            'pastes': [],
            'summary': {}
        }
        
        # Generate potential common emails for the domain
        common_names = ['admin', 'info', 'support', 'contact', 'sales', 'webmaster', 'postmaster']
        test_emails = [f"{name}@{domain}" for name in common_names]
        
        # Note: In a real implementation, you'd check actual breach databases
        # For this student project, we'll simulate the structure
        
        for email in test_emails:
            # Simulate breach check (replace with actual API calls in production)
            breach_info = self._check_email_breach(email)
            if breach_info:
                results['breached_accounts'].append({
                    'email': email,
                    'breaches': breach_info
                })
        
        results['summary'] = {
            'total_checked': len(test_emails),
            'breached_found': len(results['breached_accounts']),
            'domain': domain
        }
        
        return results
    
    def _check_email_breach(self, email):
        # Placeholder for actual breach checking
        # In production, use HaveIBeenPwned API or similar
        
        # Simulate finding some breaches for demo purposes
        # Remove this in production and implement real checks
        mock_breaches = []
        
        # This is where you'd make actual API calls
        # try:
        #     url = f"{self.hibp_url}/breachedaccount/{email}"
        #     response = requests.get(url, headers=self.headers)
        #     if response.status_code == 200:
        #         return response.json()
        # except:
        #     pass
        
        return mock_breaches
    
    def check_password_pwned(self, password):
        """Check if password exists in known breaches using k-anonymity"""
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return int(count)
            return 0
        except Exception:
            return -1