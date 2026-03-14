"""
PE Malware Static Analyzer - Analysis Engine
Handles all static analysis operations on PE files
"""

import pefile
import math
import re
import hashlib
from datetime import datetime


class PEAnalyzer:
    """Main class for analyzing PE files"""
    
    # Suspicious Windows APIs commonly used in malware
    SUSPICIOUS_APIS = {
        # Process injection APIs
        'CreateRemoteThread': 'Process Injection',
        'WriteProcessMemory': 'Process Memory Writing',
        'VirtualAllocEx': 'External Memory Allocation',
        'ReadProcessMemory': 'Process Memory Reading',
        'OpenProcess': 'Process Access',
        'QueueUserAPC': 'APC Injection',
        'NtUnmapViewOfSection': 'Process Hollowing',
        'SetThreadContext': 'Thread Context Manipulation',
        
        # Execution APIs
        'WinExec': 'Command Execution',
        'ShellExecute': 'Shell Execution',
        'ShellExecuteA': 'Shell Execution',
        'ShellExecuteW': 'Shell Execution',
        'CreateProcess': 'Process Creation',
        'system': 'System Command Execution',
        
        # Memory manipulation
        'VirtualAlloc': 'Memory Allocation',
        'VirtualProtect': 'Memory Protection Change',
        'HeapCreate': 'Heap Creation',
        'HeapAlloc': 'Heap Allocation',
        
        # Persistence APIs
        'RegSetValueEx': 'Registry Modification',
        'RegCreateKeyEx': 'Registry Key Creation',
        'CreateService': 'Service Creation',
        'StartService': 'Service Starting',
        
        # Network APIs
        'InternetOpen': 'Internet Connection',
        'InternetConnect': 'Network Connection',
        'HttpSendRequest': 'HTTP Request',
        'socket': 'Socket Creation',
        'connect': 'Network Connection',
        'send': 'Data Transmission',
        'recv': 'Data Reception',
        'WSAStartup': 'Winsock Initialization',
        
        # File manipulation
        'CreateFile': 'File Creation',
        'WriteFile': 'File Writing',
        'DeleteFile': 'File Deletion',
        'CopyFile': 'File Copying',
        'MoveFile': 'File Moving',
        
        # Evasion APIs
        'IsDebuggerPresent': 'Debugger Detection',
        'CheckRemoteDebuggerPresent': 'Remote Debugger Detection',
        'GetTickCount': 'Timing Check',
        'QueryPerformanceCounter': 'Timing Check',
        'NtSetInformationThread': 'Thread Hiding',
    }
    
    # Suspicious string patterns
    SUSPICIOUS_PATTERNS = {
        'url': r'https?://[^\s"<>]+|www\.[^\s"<>]+',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'powershell': r'powershell|pwsh|IEX|Invoke-Expression',
        'cmd': r'cmd\.exe|command\.com|/c\s+|/k\s+',
        'registry': r'HKEY_[A-Z_]+|REGISTRY\\',
        'base64': r'[A-Za-z0-9+/]{40,}={0,2}',
        'suspicious_extensions': r'\.exe|\.dll|\.bat|\.cmd|\.ps1|\.vbs|\.js',
    }
    
    def __init__(self, filepath):
        """Initialize analyzer with file path"""
        self.filepath = filepath
        self.pe = None
        self.file_data = None
        
        # Read file data
        with open(filepath, 'rb') as f:
            self.file_data = f.read()
    
    def analyze(self):
        """Perform complete analysis and return results"""
        try:
            # Parse PE file
            self.pe = pefile.PE(self.filepath)
            
            # Build analysis results
            results = {
                'file_info': self._get_file_info(),
                'pe_info': self._get_pe_info(),
                'suspicious_apis': self._analyze_imports(),
                'sections': self._analyze_sections(),
                'suspicious_strings': self._extract_strings(),
                'risk_score': 0,
                'risk_level': 'Low',
                'possible_behaviors': []
            }
            
            # Calculate risk score and behaviors
            results.update(self._calculate_risk(results))
            
            return results
            
        except pefile.PEFormatError as e:
            raise Exception(f"Invalid PE file format: {str(e)}")
        except Exception as e:
            raise Exception(f"Analysis error: {str(e)}")
        finally:
            if self.pe:
                self.pe.close()
    
    def _get_file_info(self):
        """Extract basic file information"""
        # Calculate MD5 hash
        md5_hash = hashlib.md5(self.file_data).hexdigest()
        
        # Determine file type
        if self.file_data[:2] == b'MZ':
            file_type = "PE Executable (Windows)"
        else:
            file_type = "Unknown"
        
        return {
            'file_name': self.filepath.split('/')[-1].split('\\')[-1],
            'file_type': file_type,
            'file_size': len(self.file_data),
            'md5_hash': md5_hash
        }
    
    def _get_pe_info(self):
        """Extract PE header information"""
        # Get compilation timestamp
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except:
            compile_time = f"Invalid timestamp ({timestamp})"
        
        return {
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'compilation_time': compile_time,
            'num_sections': len(self.pe.sections),
            'subsystem': self._get_subsystem_name(self.pe.OPTIONAL_HEADER.Subsystem)
        }
    
    def _get_subsystem_name(self, subsystem_id):
        """Convert subsystem ID to name"""
        subsystems = {
            1: 'Native',
            2: 'Windows GUI',
            3: 'Windows Console',
            5: 'OS/2 Console',
            7: 'POSIX Console',
            9: 'Windows CE GUI',
            10: 'EFI Application',
            11: 'EFI Boot Driver',
            12: 'EFI Runtime Driver',
            13: 'EFI ROM Image',
            14: 'Xbox',
            16: 'Windows Boot Application'
        }
        return subsystems.get(subsystem_id, f'Unknown ({subsystem_id})')
    
    def _analyze_imports(self):
        """Analyze imported APIs for suspicious functions"""
        suspicious_found = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return suspicious_found
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
            
            for func in entry.imports:
                if func.name:
                    func_name = func.name.decode('utf-8', errors='ignore')
                    
                    # Check if function is in suspicious list
                    if func_name in self.SUSPICIOUS_APIS:
                        suspicious_found.append({
                            'function': func_name,
                            'dll': dll_name,
                            'behavior': self.SUSPICIOUS_APIS[func_name]
                        })
        
        return suspicious_found
    
    def _analyze_sections(self):
        """Analyze PE sections for anomalies"""
        sections = []
        
        for section in self.pe.sections:
            # Get section name (remove null bytes)
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            # Calculate entropy
            section_data = section.get_data()
            entropy = self._calculate_entropy(section_data)
            
            # Check if entropy is suspicious (> 7.0 indicates packing/encryption)
            is_suspicious = entropy > 7.0
            
            sections.append({
                'name': name,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': round(entropy, 2),
                'suspicious': is_suspicious,
                'characteristics': self._parse_section_characteristics(section.Characteristics)
            })
        
        return sections
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        
        return entropy
    
    def _parse_section_characteristics(self, characteristics):
        """Parse section characteristics flags"""
        flags = []
        
        if characteristics & 0x20000000:
            flags.append('EXECUTE')
        if characteristics & 0x40000000:
            flags.append('READ')
        if characteristics & 0x80000000:
            flags.append('WRITE')
        if characteristics & 0x00000020:
            flags.append('CODE')
        if characteristics & 0x00000040:
            flags.append('INITIALIZED_DATA')
        if characteristics & 0x00000080:
            flags.append('UNINITIALIZED_DATA')
        
        return flags
    
    def _extract_strings(self):
        """Extract suspicious strings from binary"""
        suspicious_strings = []
        
        # Extract ASCII strings (4+ characters)
        ascii_strings = re.findall(b'[\x20-\x7E]{4,}', self.file_data)
        
        for string in ascii_strings:
            try:
                decoded = string.decode('ascii')
                
                # Check against suspicious patterns
                for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                    if re.search(pattern, decoded, re.IGNORECASE):
                        # Avoid duplicates
                        if decoded not in [s['string'] for s in suspicious_strings]:
                            suspicious_strings.append({
                                'string': decoded,
                                'type': pattern_name,
                                'category': self._get_string_category(pattern_name)
                            })
                        break
                        
            except:
                continue
        
        return suspicious_strings
    
    def _get_string_category(self, pattern_name):
        """Categorize suspicious string type"""
        categories = {
            'url': 'Network',
            'ip_address': 'Network',
            'email': 'Communication',
            'powershell': 'Execution',
            'cmd': 'Execution',
            'registry': 'Persistence',
            'base64': 'Obfuscation',
            'suspicious_extensions': 'File'
        }
        return categories.get(pattern_name, 'Other')
    
    def _calculate_risk(self, results):
        """Calculate overall risk score and identify behaviors"""
        score = 0
        behaviors = set()
        
        # Score based on suspicious APIs (10 points each, max 50)
        api_count = len(results['suspicious_apis'])
        score += min(api_count * 10, 50)
        
        for api in results['suspicious_apis']:
            behaviors.add(api['behavior'])
        
        # Score based on high entropy sections (15 points each)
        high_entropy_sections = [s for s in results['sections'] if s['suspicious']]
        score += len(high_entropy_sections) * 15
        
        if high_entropy_sections:
            behaviors.add('Packed/Encrypted Code')
        
        # Score based on suspicious strings (5 points each, max 25)
        string_score = min(len(results['suspicious_strings']) * 2, 25)
        score += string_score
        
        # Add behaviors based on string types
        for string in results['suspicious_strings']:
            if string['category'] == 'Network':
                behaviors.add('Network Communication')
            elif string['category'] == 'Execution':
                behaviors.add('Command Execution')
            elif string['category'] == 'Persistence':
                behaviors.add('Persistence Mechanism')
            elif string['category'] == 'Obfuscation':
                behaviors.add('Code Obfuscation')
        
        # Determine risk level
        if score >= 70:
            risk_level = 'High'
        elif score >= 40:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'risk_score': min(score, 100),
            'risk_level': risk_level,
            'possible_behaviors': list(behaviors)
        }