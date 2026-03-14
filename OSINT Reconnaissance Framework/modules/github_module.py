import requests
import re
import base64

class GitHubOSINT:
    def __init__(self):
        self.base_url = "https://api.github.com"
        # Note: For production, use GitHub token to avoid rate limits
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'OSINT-Framework'
        }
    
    def search_target(self, domain):
        results = {
            'repositories': [],
            'code_leaks': [],
            'users': [],
            'emails_found': []
        }
        
        # Search for code containing domain
        try:
            query = f"{domain}"
            url = f"{self.base_url}/search/code?q={query}&per_page=10"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    results['code_leaks'].append({
                        'name': item.get('name'),
                        'path': item.get('path'),
                        'repository': item.get('repository', {}).get('full_name'),
                        'url': item.get('html_url')
                    })
                    
                    # Try to get email from commits (simplified)
                    if item.get('repository', {}).get('owner', {}).get('type') == 'User':
                        user = item.get('repository', {}).get('owner', {}).get('login')
                        if user not in [u['username'] for u in results['users']]:
                            results['users'].append({
                                'username': user,
                                'profile_url': f"https://github.com/{user}",
                                'type': 'Developer'
                            })
        except Exception as e:
            results['error'] = str(e)
        
        # Search for repositories related to domain
        try:
            query = f"{domain.split('.')[0]} in:name"
            url = f"{self.base_url}/search/repositories?q={query}&per_page=5"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for repo in data.get('items', []):
                    results['repositories'].append({
                        'name': repo.get('full_name'),
                        'description': repo.get('description'),
                        'url': repo.get('html_url'),
                        'stars': repo.get('stargazers_count'),
                        'language': repo.get('language')
                    })
        except Exception:
            pass
        
        # Extract potential emails from code (pattern matching)
        email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
        # This would need actual file content analysis, simplified here
        
        return results