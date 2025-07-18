# Secret Detection Scanner

A comprehensive Python-based secret detection tool that can identify secrets in both source code and binary files.

## Features

### Source Code Detection
- **API Keys**: AWS, Azure, Google, Stripe, GitHub tokens
- **Database Credentials**: MySQL, PostgreSQL, MongoDB passwords
- **JWT Tokens**: JWT secrets and tokens
- **Private Keys**: RSA, SSH, DSA, EC private keys
- **Passwords**: Hardcoded passwords and secrets
- **OAuth Secrets**: OAuth tokens and secrets
- **Certificates**: SSL/TLS certificates
- **URLs with Credentials**: URLs containing embedded credentials

### Binary File Detection
- **Embedded Secrets**: Secrets embedded in binary files
- **String Extraction**: Extracts printable strings from binaries
- **Pattern Matching**: Detects common secret patterns in binary data

### Advanced Features
- **Multi-format Support**: Text files, binary files, configuration files
- **Encoding Detection**: Automatic encoding detection for text files
- **Confidence Scoring**: Calculates confidence levels for findings
- **Severity Classification**: High, medium, and low severity levels
- **Comprehensive Reporting**: JSON, Markdown summary, and detailed reports

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements-secret-detection.txt
```

2. For Windows users, you may need to install `python-magic-bin`:
```bash
pip install python-magic-bin
```

## Usage

### Basic Usage
```bash
python secret-detection.py /path/to/project
```

### Advanced Usage
```bash
python secret-detection.py /path/to/project --output-dir ./custom-reports --verbose
```

### Command Line Options
- `project_path`: Path to the project to scan (required)
- `--output-dir`: Output directory for reports (default: ./secret-reports)
- `--verbose, -v`: Enable verbose output

## Supported File Types

### Source Code Files
- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Java (.java)
- PHP (.php)
- Ruby (.rb)
- Go (.go)
- C# (.cs)
- C/C++ (.c, .cpp, .h)
- HTML (.html)
- XML (.xml)

### Configuration Files
- JSON (.json)
- YAML (.yml, .yaml)
- Environment files (.env*)
- Configuration files (.config, .conf)

### Binary Files
- Executables (.exe, .dll, .so, .dylib)
- Certificate files (.pem, .key, .p12, .pfx, .crt, .cer, .der)
- Data files (.bin, .dat)

## Detection Patterns

### API Keys and Tokens
- AWS Access Key ID (20 characters)
- AWS Secret Access Key (40 characters)
- Azure keys and secrets
- Google API keys
- Stripe keys
- GitHub tokens
- Generic API keys

### Database Credentials
- Database passwords
- Connection strings
- MySQL/PostgreSQL/MongoDB credentials

### Cryptographic Keys
- RSA private keys
- SSH private keys
- DSA private keys
- EC private keys
- Certificates

### Authentication
- JWT tokens and secrets
- OAuth secrets
- Bearer tokens
- Access tokens

## Output Reports

### JSON Report
Comprehensive JSON report with all findings including:
- File paths and line numbers
- Secret types and matched content
- Confidence scores and severity levels
- Descriptions and recommendations

### Summary Report (Markdown)
High-level summary including:
- Total findings count
- Findings by severity
- Findings by type
- General recommendations

### Detailed Report (Markdown)
Detailed findings organized by file:
- All findings for each file
- Line numbers and matched content
- Severity and confidence levels
- Specific recommendations

## Example Output

```
Secret detection scan completed!
Reports saved to: ./secret-reports
Total findings: 15

Files generated:
- secret-detection-report-2025-01-18_14-30-25.json
- secret-detection-summary-2025-01-18_14-30-25.md
- secret-detection-detailed-2025-01-18_14-30-25.md
- secret-detection.log
```

## Security Best Practices

### Before Running
1. Ensure you have permission to scan the target project
2. Run in a controlled environment
3. Review findings carefully before sharing reports

### After Finding Secrets
1. **Immediate Actions**:
   - Remove hardcoded secrets from source code
   - Rotate any exposed credentials
   - Update .gitignore to exclude sensitive files

2. **Long-term Solutions**:
   - Implement secret management (HashiCorp Vault, AWS Secrets Manager)
   - Use environment variables for configuration
   - Implement secure CI/CD practices
   - Regular security training for development team

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Secret Detection
on: [push, pull_request]
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: pip install -r requirements-secret-detection.txt
    - name: Run secret detection
      run: python secret-detection.py . --output-dir ./reports
    - name: Upload reports
      uses: actions/upload-artifact@v2
      with:
        name: secret-detection-reports
        path: ./reports/
```

## Troubleshooting

### Common Issues

1. **Encoding Errors**: The tool automatically detects file encoding, but some files may still cause issues
2. **Binary File Detection**: Some files may be incorrectly classified as binary
3. **False Positives**: Review findings manually, especially low-confidence ones
4. **Performance**: Large projects may take time to scan

### Performance Tips
- Exclude large binary files if not needed
- Use specific file extensions in your project
- Run scans during off-peak hours for large projects

## Contributing

To contribute to this tool:
1. Fork the repository
2. Create a feature branch
3. Add new detection patterns or features
4. Update tests and documentation
5. Submit a pull request

## License

This tool is provided as-is for security scanning purposes. Use responsibly and in accordance with applicable laws and regulations. 
