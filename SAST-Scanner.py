#!/usr/bin/env python3
"""
Comprehensive SAST (Static Application Security Testing) Scanner
Supports multiple programming languages with extensive security checks
"""

import os
import sys
import json
import re
import subprocess
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import ast
import tokenize
from io import StringIO

# Security patterns and checks
SECURITY_PATTERNS = {
    'sql_injection': [
        r'execute\s*\(\s*[\'"][^\'"]*\+\s*\w+[\'"]',
        r'cursor\.execute\s*\(\s*[\'"][^\'"]*\+\s*\w+[\'"]',
        r'\.execute\s*\(\s*f[\'"][^\'"]*\{\w+\}',
        r'raw_query\s*=\s*[\'"][^\'"]*\+\s*\w+',
        r'query\s*=\s*[\'"][^\'"]*\+\s*\w+',
    ],
    'xss': [
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\.write\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\(\s*[\'"][^\'"]*\+\s*\w+',
        r'setInterval\s*\(\s*[\'"][^\'"]*\+\s*\w+',
    ],
    'command_injection': [
        r'os\.system\s*\(',
        r'subprocess\.call\s*\(',
        r'subprocess\.Popen\s*\(',
        r'exec\s*\(',
        r'eval\s*\(',
        r'__import__\s*\(',
    ],
    'path_traversal': [
        r'open\s*\(\s*[\'"][^\'"]*\+\s*\w+',
        r'Path\s*\(\s*[\'"][^\'"]*\+\s*\w+',
        r'os\.path\.join\s*\(\s*[\'"][^\'"]*,\s*\w+',
        r'\.\.\/',
        r'\.\.\\',
    ],
    'hardcoded_secrets': [
        r'password\s*=\s*[\'"][^\'"]+[\'"]',
        r'secret\s*=\s*[\'"][^\'"]+[\'"]',
        r'api_key\s*=\s*[\'"][^\'"]+[\'"]',
        r'token\s*=\s*[\'"][^\'"]+[\'"]',
        r'private_key\s*=\s*[\'"][^\'"]+[\'"]',
        r'aws_access_key\s*=\s*[\'"][^\'"]+[\'"]',
        r'aws_secret_key\s*=\s*[\'"][^\'"]+[\'"]',
    ],
    'weak_crypto': [
        r'hashlib\.md5\s*\(',
        r'hashlib\.sha1\s*\(',
        r'cryptography\.hazmat\.primitives\.hashes\.MD5',
        r'cryptography\.hazmat\.primitives\.hashes\.SHA1',
        r'base64\.b64encode\s*\(',
        r'base64\.b64decode\s*\(',
    ],
    'insecure_random': [
        r'random\.randint\s*\(',
        r'random\.choice\s*\(',
        r'random\.random\s*\(',
        r'secrets\.token_hex\s*\(\s*8\s*\)',  # Too short
        r'secrets\.token_urlsafe\s*\(\s*8\s*\)',  # Too short
    ],
    'unsafe_deserialization': [
        r'pickle\.loads\s*\(',
        r'pickle\.load\s*\(',
        r'yaml\.load\s*\(',
        r'json\.loads\s*\(\s*request\.data',
    ],
    'insecure_headers': [
        r'Access-Control-Allow-Origin\s*:\s*[\'"]\*[\'"]',
        r'X-Frame-Options\s*:\s*[\'"]DENY[\'"]',
        r'X-Content-Type-Options\s*:\s*[\'"]nosniff[\'"]',
    ],
    'weak_ssl': [
        r'verify\s*=\s*False',
        r'check_hostname\s*=\s*False',
        r'SSLContext\s*\(\s*\)',
        r'PROTOCOL_TLSv1\s*\(\s*\)',
        r'PROTOCOL_TLSv1_1\s*\(\s*\)',
    ],
    'debug_code': [
        r'print\s*\(',
        r'debug\s*=\s*True',
        r'logging\.debug\s*\(',
        r'console\.log\s*\(',
        r'console\.debug\s*\(',
    ],
    'deprecated_functions': [
        r'urllib\.urlopen\s*\(',
        r'urllib2\.urlopen\s*\(',
        r'input\s*\(\s*\)',  # Python 2 style
        r'raw_input\s*\(\s*\)',
    ],
    'unsafe_file_operations': [
        r'os\.remove\s*\(',
        r'shutil\.rmtree\s*\(',
        r'os\.unlink\s*\(',
        r'file\.write\s*\(',
    ],
    'weak_authentication': [
        r'if\s+password\s*==\s*[\'"][^\'"]+[\'"]',
        r'if\s+user\.password\s*==\s*[\'"][^\'"]+[\'"]',
        r'check_password\s*\(\s*[\'"][^\'"]+[\'"]',
    ],
    'information_disclosure': [
        r'stack_trace\s*=\s*True',
        r'debug\s*=\s*True',
        r'verbose\s*=\s*True',
        r'error_details\s*=\s*True',
    ]
}

class SASTScanner:
    def __init__(self, project_path: str, output_dir: str):
        self.project_path = Path(project_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.results = {
            'scan_info': {
                'project_path': str(project_path),
                'scan_date': self.scan_date,
                'total_files_scanned': 0,
                'total_issues_found': 0
            },
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'sast-scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for security issues"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return issues

        # Check for security patterns
        for vuln_type, patterns in SECURITY_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                    
                    issue = {
                        'file': str(file_path),
                        'line': line_num,
                        'vulnerability_type': vuln_type,
                        'pattern': pattern,
                        'matched_code': match.group(),
                        'line_content': line_content.strip(),
                        'severity': self._get_severity(vuln_type),
                        'description': self._get_description(vuln_type),
                        'recommendation': self._get_recommendation(vuln_type)
                    }
                    issues.append(issue)

        # Language-specific checks
        if file_path.suffix == '.py':
            issues.extend(self._scan_python_file(file_path, content))
        elif file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
            issues.extend(self._scan_javascript_file(file_path, content))
        elif file_path.suffix in ['.java']:
            issues.extend(self._scan_java_file(file_path, content))
        elif file_path.suffix in ['.php']:
            issues.extend(self._scan_php_file(file_path, content))

        return issues

    def _scan_python_file(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Python-specific security checks"""
        issues = []
        
        try:
            tree = ast.parse(content)
            
            # Check for dangerous imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ['pickle', 'marshal', 'subprocess', 'os']:
                            issues.append({
                                'file': str(file_path),
                                'line': node.lineno,
                                'vulnerability_type': 'dangerous_import',
                                'pattern': f'import {alias.name}',
                                'matched_code': f'import {alias.name}',
                                'line_content': f'import {alias.name}',
                                'severity': 'medium',
                                'description': f'Dangerous import: {alias.name}',
                                'recommendation': f'Review usage of {alias.name} for security implications'
                            })
                
                elif isinstance(node, ast.Call):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ['eval', 'exec', 'input']:
                            issues.append({
                                'file': str(file_path),
                                'line': node.lineno,
                                'vulnerability_type': 'dangerous_function_call',
                                'pattern': f'{func_name}()',
                                'matched_code': f'{func_name}()',
                                'line_content': ast.unparse(node),
                                'severity': 'high',
                                'description': f'Dangerous function call: {func_name}',
                                'recommendation': f'Avoid using {func_name} in production code'
                            })
        
        except SyntaxError:
            self.logger.warning(f"Syntax error in {file_path}, skipping AST analysis")
        
        return issues

    def _scan_javascript_file(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """JavaScript-specific security checks"""
        issues = []
        
        # Check for dangerous patterns
        dangerous_patterns = {
            'eval_usage': r'eval\s*\(',
            'innerHTML_usage': r'innerHTML\s*=',
            'document_write': r'document\.write\s*\(',
            'setTimeout_string': r'setTimeout\s*\(\s*[\'"][^\'"]*\+\s*\w+',
            'setInterval_string': r'setInterval\s*\(\s*[\'"][^\'"]*\+\s*\w+',
            'localStorage_sensitive': r'localStorage\.setItem\s*\(\s*[\'"](password|token|secret)',
            'sessionStorage_sensitive': r'sessionStorage\.setItem\s*\(\s*[\'"](password|token|secret)',
        }
        
        for vuln_type, pattern in dangerous_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'file': str(file_path),
                    'line': line_num,
                    'vulnerability_type': vuln_type,
                    'pattern': pattern,
                    'matched_code': match.group(),
                    'line_content': content.split('\n')[line_num - 1].strip(),
                    'severity': 'high',
                    'description': f'JavaScript security issue: {vuln_type}',
                    'recommendation': 'Review and secure JavaScript code'
                })
        
        return issues

    def _scan_java_file(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Java-specific security checks"""
        issues = []
        
        java_patterns = {
            'sql_injection': r'executeQuery\s*\(\s*[\'"][^\'"]*\+\s*\w+[\'"]',
            'command_injection': r'Runtime\.getRuntime\(\)\.exec\s*\(',
            'reflection_usage': r'Class\.forName\s*\(',
            'serialization': r'ObjectInputStream\s*\(',
            'weak_random': r'Math\.random\s*\(',
        }
        
        for vuln_type, pattern in java_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'file': str(file_path),
                    'line': line_num,
                    'vulnerability_type': vuln_type,
                    'pattern': pattern,
                    'matched_code': match.group(),
                    'line_content': content.split('\n')[line_num - 1].strip(),
                    'severity': 'high',
                    'description': f'Java security issue: {vuln_type}',
                    'recommendation': 'Review and secure Java code'
                })
        
        return issues

    def _scan_php_file(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """PHP-specific security checks"""
        issues = []
        
        php_patterns = {
            'sql_injection': r'mysql_query\s*\(\s*[\'"][^\'"]*\.\s*\$\w+',
            'command_injection': r'system\s*\(',
            'eval_usage': r'eval\s*\(',
            'file_inclusion': r'include\s*\(\s*\$\w+',
            'weak_random': r'rand\s*\(',
        }
        
        for vuln_type, pattern in php_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'file': str(file_path),
                    'line': line_num,
                    'vulnerability_type': vuln_type,
                    'pattern': pattern,
                    'matched_code': match.group(),
                    'line_content': content.split('\n')[line_num - 1].strip(),
                    'severity': 'high',
                    'description': f'PHP security issue: {vuln_type}',
                    'recommendation': 'Review and secure PHP code'
                })
        
        return issues

    def _get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type"""
        high_severity = ['sql_injection', 'command_injection', 'xss', 'path_traversal']
        medium_severity = ['hardcoded_secrets', 'weak_crypto', 'unsafe_deserialization']
        
        if vuln_type in high_severity:
            return 'high'
        elif vuln_type in medium_severity:
            return 'medium'
        else:
            return 'low'

    def _get_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            'sql_injection': 'Potential SQL injection vulnerability',
            'xss': 'Potential Cross-Site Scripting (XSS) vulnerability',
            'command_injection': 'Potential command injection vulnerability',
            'path_traversal': 'Potential path traversal vulnerability',
            'hardcoded_secrets': 'Hardcoded secrets or credentials detected',
            'weak_crypto': 'Weak cryptographic algorithm detected',
            'insecure_random': 'Insecure random number generation',
            'unsafe_deserialization': 'Unsafe deserialization detected',
            'debug_code': 'Debug code found in production',
            'deprecated_functions': 'Deprecated or unsafe function usage',
            'unsafe_file_operations': 'Unsafe file operation detected',
            'weak_authentication': 'Weak authentication mechanism',
            'information_disclosure': 'Potential information disclosure'
        }
        return descriptions.get(vuln_type, f'Security issue: {vuln_type}')

    def _get_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries or ORM',
            'xss': 'Use proper output encoding and validation',
            'command_injection': 'Avoid command execution with user input',
            'path_traversal': 'Validate and sanitize file paths',
            'hardcoded_secrets': 'Use environment variables or secret management',
            'weak_crypto': 'Use strong cryptographic algorithms',
            'insecure_random': 'Use cryptographically secure random generators',
            'unsafe_deserialization': 'Use safe deserialization methods',
            'debug_code': 'Remove debug code from production',
            'deprecated_functions': 'Use modern, secure alternatives',
            'unsafe_file_operations': 'Implement proper file operation security',
            'weak_authentication': 'Implement strong authentication mechanisms',
            'information_disclosure': 'Limit information exposure'
        }
        return recommendations.get(vuln_type, 'Review and secure the code')

    def scan_project(self):
        """Scan the entire project"""
        self.logger.info(f"Starting SAST scan for: {self.project_path}")
        
        # Supported file extensions
        supported_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', 
            '.rb', '.go', '.cs', '.cpp', '.c', '.h', '.html', '.xml'
        }
        
        total_files = 0
        total_issues = 0
        
        for file_path in self.project_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                # Skip common directories
                if any(part in ['node_modules', 'vendor', '.git', 'build', 'dist', '__pycache__'] 
                       for part in file_path.parts):
                    continue
                
                self.logger.info(f"Scanning: {file_path}")
                issues = self.scan_file(file_path)
                
                if issues:
                    self.results['vulnerabilities'].extend(issues)
                    total_issues += len(issues)
                
                total_files += 1
        
        self.results['scan_info']['total_files_scanned'] = total_files
        self.results['scan_info']['total_issues_found'] = total_issues
        
        self.logger.info(f"Scan completed. Found {total_issues} issues in {total_files} files")
        
        # Generate reports
        self._generate_reports()

    def _generate_reports(self):
        """Generate various report formats"""
        # JSON report
        with open(self.output_dir / f'sast-report-{self.scan_date}.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Summary report
        self._generate_summary_report()
        
        # Detailed report by vulnerability type
        self._generate_detailed_report()

    def _generate_summary_report(self):
        """Generate a summary report"""
        summary_file = self.output_dir / f'sast-summary-{self.scan_date}.md'
        
        with open(summary_file, 'w') as f:
            f.write(f"# SAST Scan Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Project: {self.project_path}\n\n")
            
            f.write("## Scan Summary\n")
            f.write(f"- **Files Scanned:** {self.results['scan_info']['total_files_scanned']}\n")
            f.write(f"- **Issues Found:** {self.results['scan_info']['total_issues_found']}\n")
            f.write(f"- **Scan Date:** {self.scan_date}\n\n")
            
            # Group by severity
            high_issues = [i for i in self.results['vulnerabilities'] if i['severity'] == 'high']
            medium_issues = [i for i in self.results['vulnerabilities'] if i['severity'] == 'medium']
            low_issues = [i for i in self.results['vulnerabilities'] if i['severity'] == 'low']
            
            f.write("## Issues by Severity\n")
            f.write(f"- **High:** {len(high_issues)}\n")
            f.write(f"- **Medium:** {len(medium_issues)}\n")
            f.write(f"- **Low:** {len(low_issues)}\n\n")
            
            # Group by vulnerability type
            vuln_types = {}
            for issue in self.results['vulnerabilities']:
                vuln_type = issue['vulnerability_type']
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = 0
                vuln_types[vuln_type] += 1
            
            f.write("## Issues by Type\n")
            for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- **{vuln_type}:** {count}\n")
            
            f.write("\n## Recommendations\n")
            f.write("1. Address high severity issues first\n")
            f.write("2. Review and fix medium severity issues\n")
            f.write("3. Consider low severity issues for code quality\n")
            f.write("4. Implement secure coding practices\n")
            f.write("5. Regular security training for development team\n")

    def _generate_detailed_report(self):
        """Generate detailed report with all issues"""
        detailed_file = self.output_dir / f'sast-detailed-{self.scan_date}.md'
        
        with open(detailed_file, 'w') as f:
            f.write(f"# Detailed SAST Scan Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Project: {self.project_path}\n\n")
            
            # Group by file
            files_issues = {}
            for issue in self.results['vulnerabilities']:
                file_path = issue['file']
                if file_path not in files_issues:
                    files_issues[file_path] = []
                files_issues[file_path].append(issue)
            
            for file_path, issues in files_issues.items():
                f.write(f"## File: {file_path}\n\n")
                
                for issue in issues:
                    f.write(f"### {issue['vulnerability_type'].replace('_', ' ').title()}\n")
                    f.write(f"- **Severity:** {issue['severity']}\n")
                    f.write(f"- **Line:** {issue['line']}\n")
                    f.write(f"- **Description:** {issue['description']}\n")
                    f.write(f"- **Code:** `{issue['line_content']}`\n")
                    f.write(f"- **Recommendation:** {issue['recommendation']}\n\n")

def main():
    parser = argparse.ArgumentParser(description='Comprehensive SAST Scanner')
    parser.add_argument('project_path', help='Path to the project to scan')
    parser.add_argument('--output-dir', default='./sast-reports', help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.project_path):
        print(f"Error: Project path '{args.project_path}' does not exist")
        sys.exit(1)
    
    scanner = SASTScanner(args.project_path, args.output_dir)
    scanner.scan_project()
    
    print(f"\nSAST scan completed!")
    print(f"Reports saved to: {args.output_dir}")
    print(f"Total issues found: {scanner.results['scan_info']['total_issues_found']}")

if __name__ == '__main__':
    main() 
