import requests
import json
from datetime import datetime

class ArchiveLookup:
    def __init__(self):
        self.base_url = "http://web.archive.org/cdx/search/cdx"
        self.snapshot_url = "http://web.archive.org/web"
    
    def get_snapshots(self, domain):
        results = {
            'total_snapshots': 0,
            'first_seen': None,
            'last_seen': None,
            'interesting_snapshots': [],
            'url_changes': []
        }
        
        try:
            # Query Wayback Machine CDX API
            params = {
                'url': domain,
                'output': 'json',
                'collapse': 'timestamp:8',  # Collapse by day
                'limit': 100
            }
            
            response = requests.get(self.base_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if len(data) > 1:  # First row is header
                    results['total_snapshots'] = len(data) - 1
                    
                    # Parse timestamps
                    timestamps = [row[1] for row in data[1:]]
                    if timestamps:
                        first_ts = min(timestamps)
                        last_ts = max(timestamps)
                        
                        results['first_seen'] = self._format_timestamp(first_ts)
                        results['last_seen'] = self._format_timestamp(last_ts)
                    
                    # Get interesting snapshots (first few)
                    for row in data[1:6]:
                        timestamp = row[1]
                        original_url = row[2]
                        mimetype = row[3]
                        statuscode = row[4]
                        
                        archive_url = f"{self.snapshot_url}/{timestamp}/{original_url}"
                        
                        results['interesting_snapshots'].append({
                            'date': self._format_timestamp(timestamp),
                            'url': archive_url,
                            'status': statuscode,
                            'type': mimetype
                        })
                    
                    # Detect URL structure changes
                    unique_paths = set()
                    for row in data[1:20]:
                        path = row[2].replace(domain, '')
                        if path and path != '/':
                            unique_paths.add(path)
                    
                    results['url_changes'] = list(unique_paths)[:10]
            
            # Also check for specific file types in history
            file_extensions = ['pdf', 'doc', 'xls', 'zip', 'sql', 'backup']
            for ext in file_extensions:
                try:
                    params = {
                        'url': f'*.{domain}/*.{ext}',
                        'output': 'json',
                        'limit': 5
                    }
                    resp = requests.get(self.base_url, params=params, timeout=10)
                    if resp.status_code == 200 and len(resp.json()) > 1:
                        results.setdefault('file_history', []).append({
                            'type': ext,
                            'count': len(resp.json()) - 1
                        })
                except Exception:
                    continue
                    
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _format_timestamp(self, ts):
        try:
            return datetime.strptime(ts, '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return ts