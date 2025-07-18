#!/usr/bin/env python3
"""
Comprehensive Secret Detection Scanner
Supports detection of secrets in source code and binary files
"""

import os
import sys
import json
import re
import subprocess
import argparse
import logging
import hashlib
import base64
import binascii
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import magic
import chardet
import yaml
from dataclasses import dataclass
from enum import Enum

class SecretType(Enum):
    API_KEY = "api_key"
    AWS_CREDENTIALS = "aws_credentials"
    DATABASE_CREDENTIALS = "database_credentials"
    JWT_TOKEN = "jwt_token"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    URL_WITH_CREDENTIALS = "url_with_credentials"
    HARDCODED_SECRET = "hardcoded_secret"
    ENCRYPTION_KEY = "encryption_key"
    OAUTH_SECRET = "oauth_secret"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    BINARY_SECRET = "binary_secret"

@dataclass
class SecretFinding:
    file_path: str
    line_number: Optional[int]
    secret_type: SecretType
    matched_content: str
    confidence: float
    description: str
    recommendation: str
    severity: str

class SecretDetector:
    def __init__(self, project_path: str, output_dir: str):
        self.project_path = Path(project_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.findings = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'secret-detection.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize patterns
        self._init_patterns()
        
    def _init_patterns(self):
        """Initialize secret detection patterns"""
        self.patterns = {
            SecretType.API_KEY: [
                r'(?i)(api[_-]?key|apikey|api_key)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
                r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*[\'"][A-Z0-9]{20}[\'"]',
                r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*[\'"][A-Za-z0-9/+=]{40}[\'"]',
                r'(?i)(azure[_-]?key|azure[_-]?secret)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
                r'(?i)(google[_-]?api[_-]?key|google[_-]?secret)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
                r'(?i)(stripe[_-]?key|stripe[_-]?secret)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
                r'(?i)(github[_-]?token|github[_-]?secret)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
            ],
            SecretType.DATABASE_CREDENTIALS: [
                r'(?i)(database[_-]?password|db[_-]?password|db_password)\s*[=:]\s*[\'"][^\'"]{5,}[\'"]',
                r'(?i)(mysql[_-]?password|postgres[_-]?password|mongodb[_-]?password)\s*[=:]\s*[\'"][^\'"]{5,}[\'"]',
                r'(?i)(connection[_-]?string|connectionstring)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
            ],
            SecretType.JWT_TOKEN: [
                r'(?i)(jwt[_-]?secret|jwt_secret|jwt[_-]?token)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
                r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            ],
            SecretType.PRIVATE_KEY: [
                r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
                r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----',
                r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
                r'(?i)(private[_-]?key|privatekey|rsa[_-]?private[_-]?key)\s*[=:]\s*[\'"][^\'"]{50,}[\'"]',
            ],
            SecretType.PASSWORD: [
                r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{5,}[\'"]',
                r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
            ],
            SecretType.URL_WITH_CREDENTIALS: [
                r'https?://[^/]+:[^@]+@[^/]+',
                r'ftp://[^/]+:[^@]+@[^/]+',
                r'ssh://[^/]+:[^@]+@[^/]+',
            ],
            SecretType.OAUTH_SECRET: [
                r'(?i)(oauth[_-]?secret|oauth_secret)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
                r'(?i)(bearer[_-]?token|access[_-]?token)\s*[=:]\s*[\'"][^\'"]{10,}[\'"]',
            ],
            SecretType.SSH_KEY: [
                r'(?i)(ssh[_-]?key|sshkey|ssh[_-]?private[_-]?key)\s*[=:]\s*[\'"][^\'"]{50,}[\'"]',
                r'-----BEGIN\s+SSH\s+PRIVATE\s+KEY-----',
            ],
            SecretType.CERTIFICATE: [
                r'-----BEGIN\s+CERTIFICATE-----',
                r'-----BEGIN\s+X509\s+CERTIFICATE-----',
                r'-----BEGIN\s+TRUSTED\s+CERTIFICATE-----',
            ],
        }
        
        # Binary patterns for common secret formats
        self.binary_patterns = {
            SecretType.BINARY_SECRET: [
                rb'\x00\x00\x00\x00\x00\x00\x00\x00',  # Null bytes pattern
                rb'password',  # Common password strings in binaries
                rb'secret',
                rb'key',
                rb'token',
                rb'credential',
            ]
        }

    def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file for secrets"""
        findings = []
        
        try:
            # Check if file is binary
            if self._is_binary_file(file_path):
                findings.extend(self._scan_binary_file(file_path))
            else:
                findings.extend(self._scan_text_file(file_path))
                
        except Exception as e:
            self.logger.warning(f"Could not scan file {file_path}: {e}")
            
        return findings

    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk or not chunk.decode('utf-8', errors='ignore').isprintable()
        except:
            return False

    def _scan_text_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan text file for secrets"""
        findings = []
        
        try:
            # Detect encoding
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                encoding = chardet.detect(raw_data)['encoding'] or 'utf-8'
            
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
        except Exception as e:
            self.logger.warning(f"Could not read text file {file_path}: {e}")
            return findings

        # Check each pattern type
        for secret_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                    
                    # Calculate confidence based on pattern strength
                    confidence = self._calculate_confidence(secret_type, match.group(), line_content)
                    
                    finding = SecretFinding(
                        file_path=str(file_path),
                        line_number=line_num,
                        secret_type=secret_type,
                        matched_content=match.group(),
                        confidence=confidence,
                        description=self._get_description(secret_type),
                        recommendation=self._get_recommendation(secret_type),
                        severity=self._get_severity(secret_type, confidence)
                    )
                    findings.append(finding)

        return findings

    def _scan_binary_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan binary file for secrets"""
        findings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
        except Exception as e:
            self.logger.warning(f"Could not read binary file {file_path}: {e}")
            return findings

        # Check for embedded text secrets in binary
        try:
            # Extract printable strings
            strings = self._extract_strings(content)
            
            for string in strings:
                if len(string) > 10:  # Only check longer strings
                    for secret_type, patterns in self.patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, string, re.IGNORECASE):
                                finding = SecretFinding(
                                    file_path=str(file_path),
                                    line_number=None,
                                    secret_type=secret_type,
                                    matched_content=string[:100] + "..." if len(string) > 100 else string,
                                    confidence=0.7,  # Lower confidence for binary files
                                    description=f"Secret found in binary file: {self._get_description(secret_type)}",
                                    recommendation=self._get_recommendation(secret_type),
                                    severity="medium"
                                )
                                findings.append(finding)
                                break
        except Exception as e:
            self.logger.warning(f"Error scanning binary file {file_path}: {e}")

        # Check binary patterns
        for secret_type, patterns in self.binary_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    finding = SecretFinding(
                        file_path=str(file_path),
                        line_number=None,
                        secret_type=secret_type,
                        matched_content=f"Binary pattern: {pattern}",
                        confidence=0.6,
                        description="Potential secret pattern found in binary file",
                        recommendation="Review binary file for embedded secrets",
                        severity="medium"
                    )
                    findings.append(finding)

        return findings

    def _extract_strings(self, binary_content: bytes) -> List[str]:
        """Extract printable strings from binary content"""
        strings = []
        current_string = ""
        
        for byte in binary_content:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:  # Minimum string length
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= 4:
            strings.append(current_string)
            
        return strings

    def _calculate_confidence(self, secret_type: SecretType, matched_content: str, line_content: str) -> float:
        """Calculate confidence level for a finding"""
        base_confidence = 0.5
        
        # Adjust based on secret type
        if secret_type in [SecretType.API_KEY, SecretType.AWS_CREDENTIALS]:
            base_confidence = 0.8
        elif secret_type in [SecretType.PRIVATE_KEY, SecretType.SSH_KEY]:
            base_confidence = 0.9
        elif secret_type == SecretType.JWT_TOKEN:
            base_confidence = 0.7
            
        # Adjust based on content length and format
        if len(matched_content) > 50:
            base_confidence += 0.1
        if re.search(r'[A-Za-z0-9+/=]{20,}', matched_content):
            base_confidence += 0.1
            
        # Adjust based on context
        if any(keyword in line_content.lower() for keyword in ['password', 'secret', 'key', 'token']):
            base_confidence += 0.1
            
        return min(base_confidence, 1.0)

    def _get_description(self, secret_type: SecretType) -> str:
        """Get description for secret type"""
        descriptions = {
            SecretType.API_KEY: "API key or access token detected",
            SecretType.AWS_CREDENTIALS: "AWS credentials detected",
            SecretType.DATABASE_CREDENTIALS: "Database credentials detected",
            SecretType.JWT_TOKEN: "JWT token or secret detected",
            SecretType.PRIVATE_KEY: "Private key detected",
            SecretType.PASSWORD: "Password or secret detected",
            SecretType.URL_WITH_CREDENTIALS: "URL with embedded credentials detected",
            SecretType.OAUTH_SECRET: "OAuth secret or token detected",
            SecretType.SSH_KEY: "SSH private key detected",
            SecretType.CERTIFICATE: "Certificate detected",
            SecretType.BINARY_SECRET: "Potential secret in binary file",
        }
        return descriptions.get(secret_type, f"Secret detected: {secret_type.value}")

    def _get_recommendation(self, secret_type: SecretType) -> str:
        """Get recommendation for secret type"""
        recommendations = {
            SecretType.API_KEY: "Remove hardcoded API keys and use environment variables or secret management",
            SecretType.AWS_CREDENTIALS: "Use AWS IAM roles or environment variables for credentials",
            SecretType.DATABASE_CREDENTIALS: "Use connection string builders or environment variables",
            SecretType.JWT_TOKEN: "Store JWT secrets in secure configuration management",
            SecretType.PRIVATE_KEY: "Store private keys in secure key management systems",
            SecretType.PASSWORD: "Use password managers or secure configuration",
            SecretType.URL_WITH_CREDENTIALS: "Separate credentials from URLs and use secure configuration",
            SecretType.OAUTH_SECRET: "Store OAuth secrets in secure configuration management",
            SecretType.SSH_KEY: "Store SSH keys in secure key management systems",
            SecretType.CERTIFICATE: "Store certificates in secure certificate management",
            SecretType.BINARY_SECRET: "Review binary files for embedded secrets and remove them",
        }
        return recommendations.get(secret_type, "Review and secure the detected secret")

    def _get_severity(self, secret_type: SecretType, confidence: float) -> str:
        """Get severity level for secret type"""
        if confidence > 0.8:
            return "high"
        elif confidence > 0.6:
            return "medium"
        else:
            return "low"

    def scan_project(self):
        """Scan the entire project for secrets"""
        self.logger.info(f"Starting secret detection scan for: {self.project_path}")
        
        # Supported file extensions
        supported_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', 
            '.rb', '.go', '.cs', '.cpp', '.c', '.h', '.html', '.xml',
            '.json', '.yaml', '.yml', '.env', '.config', '.conf',
            '.pem', '.key', '.p12', '.pfx', '.crt', '.cer', '.der',
            '.exe', '.dll', '.so', '.dylib', '.bin', '.dat'
        }
        
        total_files = 0
        total_findings = 0
        
        for file_path in self.project_path.rglob('*'):
            if file_path.is_file():
                # Skip common directories
                if any(part in ['node_modules', 'vendor', '.git', 'build', 'dist', '__pycache__', '.venv'] 
                       for part in file_path.parts):
                    continue
                
                # Check if file has supported extension or is binary
                if (file_path.suffix in supported_extensions or 
                    self._is_binary_file(file_path)):
                    
                    self.logger.info(f"Scanning: {file_path}")
                    findings = self.scan_file(file_path)
                    
                    if findings:
                        self.findings.extend(findings)
                        total_findings += len(findings)
                    
                    total_files += 1
        
        self.logger.info(f"Scan completed. Found {total_findings} potential secrets in {total_files} files")
        
        # Generate reports
        self._generate_reports()

    def _generate_reports(self):
        """Generate various report formats"""
        # JSON report
        with open(self.output_dir / f'secret-detection-report-{self.scan_date}.json', 'w') as f:
            json.dump(self._serialize_findings(), f, indent=2)
        
        # Summary report
        self._generate_summary_report()
        
        # Detailed report
        self._generate_detailed_report()

    def _serialize_findings(self) -> Dict[str, Any]:
        """Serialize findings for JSON output"""
        return {
            'scan_info': {
                'project_path': str(self.project_path),
                'scan_date': self.scan_date,
                'total_findings': len(self.findings)
            },
            'findings': [
                {
                    'file_path': finding.file_path,
                    'line_number': finding.line_number,
                    'secret_type': finding.secret_type.value,
                    'matched_content': finding.matched_content,
                    'confidence': finding.confidence,
                    'description': finding.description,
                    'recommendation': finding.recommendation,
                    'severity': finding.severity
                }
                for finding in self.findings
            ]
        }

    def _generate_summary_report(self):
        """Generate a summary report"""
        summary_file = self.output_dir / f'secret-detection-summary-{self.scan_date}.md'
        
        with open(summary_file, 'w') as f:
            f.write(f"# Secret Detection Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Project: {self.project_path}\n\n")
            
            f.write("## Scan Summary\n")
            f.write(f"- **Total Findings:** {len(self.findings)}\n")
            f.write(f"- **Scan Date:** {self.scan_date}\n\n")
            
            # Group by severity
            high_findings = [f for f in self.findings if f.severity == 'high']
            medium_findings = [f for f in self.findings if f.severity == 'medium']
            low_findings = [f for f in self.findings if f.severity == 'low']
            
            f.write("## Findings by Severity\n")
            f.write(f"- **High:** {len(high_findings)}\n")
            f.write(f"- **Medium:** {len(medium_findings)}\n")
            f.write(f"- **Low:** {len(low_findings)}\n\n")
            
            # Group by secret type
            secret_types = {}
            for finding in self.findings:
                secret_type = finding.secret_type.value
                if secret_type not in secret_types:
                    secret_types[secret_type] = 0
                secret_types[secret_type] += 1
            
            f.write("## Findings by Type\n")
            for secret_type, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- **{secret_type}:** {count}\n")
            
            f.write("\n## Recommendations\n")
            f.write("1. Address high severity findings immediately\n")
            f.write("2. Review and fix medium severity findings\n")
            f.write("3. Consider low severity findings for code quality\n")
            f.write("4. Implement secret management solutions\n")
            f.write("5. Add secrets to .gitignore\n")
            f.write("6. Regular security training for development team\n")

    def _generate_detailed_report(self):
        """Generate detailed report with all findings"""
        detailed_file = self.output_dir / f'secret-detection-detailed-{self.scan_date}.md'
        
        with open(detailed_file, 'w') as f:
            f.write(f"# Detailed Secret Detection Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Project: {self.project_path}\n\n")
            
            # Group by file
            files_findings = {}
            for finding in self.findings:
                file_path = finding.file_path
                if file_path not in files_findings:
                    files_findings[file_path] = []
                files_findings[file_path].append(finding)
            
            for file_path, findings in files_findings.items():
                f.write(f"## File: {file_path}\n\n")
                
                for finding in findings:
                    f.write(f"### {finding.secret_type.value.replace('_', ' ').title()}\n")
                    f.write(f"- **Severity:** {finding.severity}\n")
                    f.write(f"- **Confidence:** {finding.confidence:.2f}\n")
                    if finding.line_number:
                        f.write(f"- **Line:** {finding.line_number}\n")
                    f.write(f"- **Description:** {finding.description}\n")
                    f.write(f"- **Matched Content:** `{finding.matched_content[:100]}{'...' if len(finding.matched_content) > 100 else ''}`\n")
                    f.write(f"- **Recommendation:** {finding.recommendation}\n\n")

def main():
    parser = argparse.ArgumentParser(description='Comprehensive Secret Detection Scanner')
    parser.add_argument('project_path', help='Path to the project to scan')
    parser.add_argument('--output-dir', default='./secret-reports', help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.project_path):
        print(f"Error: Project path '{args.project_path}' does not exist")
        sys.exit(1)
    
    detector = SecretDetector(args.project_path, args.output_dir)
    detector.scan_project()
    
    print(f"\nSecret detection scan completed!")
    print(f"Reports saved to: {args.output_dir}")
    print(f"Total findings: {len(detector.findings)}")

if __name__ == '__main__':
    main() 
