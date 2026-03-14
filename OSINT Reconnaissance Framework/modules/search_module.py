import requests
from bs4 import BeautifulSoup
import urllib.parse

class SearchIntel:
    def __init__(self):
        self.dorks = []
        self.findings = []
    
    def dork_target(self, domain):
        results = {
            'google_dorks': [],
            'sensitive_files': [],
            'exposed_directories': [],
            'login_pages': [],
            'subdomains': []
        }
        
        # Google Dork queries (simulated - in production use SERP APIs)
        dork_queries = [
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:docx',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} ext:sql|ext:db|ext:backup',
            f'site:*.{domain}',
            f'intitle:"index of" site:{domain}',
            f'filetype:env site:{domain}',
            f'filetype:config site:{domain}'
        ]
        
        for dork in dork_queries:
            results['google_dorks'].append({
                'query': dork,
                'description': self._get_dork_description(dork),
                'url': f'https://www.google.com/search?q={urllib.parse.quote(dork)}'
            })
        
        # Try to fetch robots.txt and sitemap
        try:
            robots_url = f"https://{domain}/robots.txt"
            response = requests.get(robots_url, timeout=5)
            if response.status_code == 200:
                results['robots_txt'] = response.text
        except Exception:
            results['robots_txt'] = 'Not accessible'
        
        # Try sitemap.xml
        try:
            sitemap_url = f"https://{domain}/sitemap.xml"
            response = requests.get(sitemap_url, timeout=5)
            if response.status_code == 200:
                results['sitemap_xml'] = 'Found'
            else:
                results['sitemap_xml'] = 'Not found'
        except Exception:
            results['sitemap_xml'] = 'Not accessible'
        
        return results
    
    def _get_dork_description(self, dork):
        descriptions = {
            'filetype:pdf': 'PDF documents that may contain sensitive information',
            'filetype:docx': 'Word documents',
            'inurl:admin': 'Potential admin panels',
            'inurl:login': 'Login pages',
            'intitle:"index of"': 'Exposed directory listings',
            'ext:sql': 'Database files',
            'filetype:env': 'Environment configuration files',
            'filetype:config': 'Configuration files'
        }
        
        for key, desc in descriptions.items():
            if key in dork:
                return desc
        return 'Custom search'