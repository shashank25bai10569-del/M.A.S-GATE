import re
import os

class PIIDetector:
    """
    Detects Personally Identifiable Information in files
    """
    
    # PII Patterns
    PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}',
        'ssn': r'\d{3}-\d{2}-\d{4}',
        'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
        'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'passport': r'[A-Z]{1,2}[0-9]{6,9}',
        'driver_license': r'[A-Z]{1,2}[0-9]{5,8}',
        'date_of_birth': r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        'address': r'\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)',
    }
    
    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.PATTERNS.items()
        }
    
    def scan_text(self, text):
        """Scan text for PII"""
        findings = []
        
        for pii_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    'type': pii_type,
                    'count': len(matches),
                    'examples': matches[:3],  # First 3 examples
                    'severity': self._get_severity(pii_type)
                })
        
        return findings
    
    def scan_file(self, file_path, max_size=10*1024*1024):
        """Scan file for PII"""
        findings = []
        
        if not os.path.exists(file_path):
            return [{'type': 'error', 'message': 'File not found'}]
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                return [{'type': 'error', 'message': 'File too large for PII scan'}]
            
            # Try to read as text
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    findings = self.scan_text(content)
            except:
                # Binary file - limited scan
                with open(file_path, 'rb') as f:
                    data = f.read(1024*1024)  # First 1MB
                    # Try to decode as ASCII
                    text = data.decode('ascii', errors='ignore')
                    findings = self.scan_text(text)
                    
        except Exception as e:
            findings.append({'type': 'error', 'message': str(e)})
        
        return findings
    
    def _get_severity(self, pii_type):
        """Get severity level for PII type"""
        high_severity = ['ssn', 'credit_card', 'passport']
        medium_severity = ['email', 'phone', 'driver_license', 'address']
        
        if pii_type in high_severity:
            return 'HIGH'
        elif pii_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_report(self, findings):
        """Generate a summary report"""
        if not findings:
            return {'status': 'clean', 'message': 'No PII detected'}
        
        # Filter out error messages
        pii_findings = [f for f in findings if f['type'] != 'error']
        errors = [f for f in findings if f['type'] == 'error']
        
        report = {
            'status': 'pii_detected' if pii_findings else 'error',
            'total_findings': len(pii_findings),
            'severity_counts': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'details': pii_findings,
            'errors': errors
        }
        
        for f in pii_findings:
            severity = f.get('severity', 'LOW')
            report['severity_counts'][severity] += 1
        
        return report

# Initialize detector
pii_detector = PIIDetector()