# 🛡️ CYLINDER
  
![IDOR Scanner Banner](https://user-images.githubusercontent.com/74038190/225813708-98b745f2-7d22-48cf-9150-083f1b00d6c9.gif)

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Contributions welcome](https://img.shields.io/badge/Contributions-welcome-orange.svg)](https://github.com/yourusername/idor-scanner/issues)

**Cylinder is a sophisticated cybersecurity tool for identifying IDOR vulnerabilities during bug bounty hunting**

---

## 🚀 Features

- 🔍 **Multi-Vector Detection** - Tests for multiple IDOR vulnerability types
- 🔄 **Parameter Pollution** - Advanced parameter manipulation techniques
- 📡 **API Endpoint Discovery** - Automatically finds potential vulnerable endpoints
- 🔐 **JWT Token Analysis** - Identifies flaws in JWT implementation
- ⚡ **Race Condition Testing** - Detects timing-based access control issues
- 🔗 **GraphQL Vulnerability Detection** - GraphQL-specific IDOR testing
- 🛠️ **Mass Assignment Testing** - Detects object property manipulation flaws
- 📊 **Comprehensive Reporting** - Detailed vulnerability reports in JSON format

<div align="center">
  
![Tool Demo](https://user-images.githubusercontent.com/74038190/216122041-518ac897-8d92-4c6b-9b3f-ca01dcaf38ee.png)

</div>

## 📋 Requirements

```
Python 3.8+
requests
rich
```

## 🔧 Installation

```bash
# Clone this repository
git clone https://github.com/yourusername/idor-scanner.git

# Navigate to the project
cd idor-scanner

# Install requirements
pip install -r requirements.txt
```

## 💻 Usage

```bash
python idor_scanner.py -u https://target-website.com -c "session=abc123" -v -o results.json
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL (required) |
| `-c, --cookies` | Cookies for authenticated testing |
| `-H, --headers` | Custom HTTP headers |
| `-i, --ids` | Test IDs (comma-separated) |
| `-v, --verbose` | Enable detailed output |
| `-t, --timeout` | Request timeout in seconds |
| `-p, --proxy` | HTTP/HTTPS proxy (e.g. Burp Suite) |
| `-o, --output` | Save results to JSON file |
| `--no-ssl-verify` | Disable SSL verification |
| `--threads` | Number of concurrent threads |
| `--jwt` | JWT token for testing |
| `--graphql` | Enable GraphQL-specific testing |

## 📊 Example Output

```json
{
  "target": "https://example.com",
  "timestamp": "2025-03-19 14:30:45",
  "findings": [
    {
      "type": "IDOR with Sensitive Data",
      "url": "https://example.com/api/user/5",
      "description": "Path parameter IDOR test: replaced '1' with '5'",
      "status": 200,
      "response_sample": "{\"id\":5,\"username\":\"admin\",\"email\":\"admin@example.com\"}"
    }
  ]
}
```

<div align="center">
  
![Security Testing](https://user-images.githubusercontent.com/74038190/212284158-e840e285-664b-44d7-b79b-e264b5e54825.gif)

</div>

## ⚠️ Disclaimer

This tool is for **ethical security research and bug bounty hunting only**. Always:

- Get explicit permission before testing any website
- Only test systems you are authorized to test
- Follow the scope and rules of bug bounty programs
- Be mindful of the potential impact of your testing

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yourusername/idor-scanner/issues).

## 🙏 Acknowledgements

- Thanks to the ethical hacking community for inspiration
- Special thanks to all contributors and bug bounty platforms

<div align="center">
  
![Thank You](https://user-images.githubusercontent.com/74038190/212284100-561aa473-3905-4a80-b561-0d28506553ee.gif)

</div>

# Cylinder - Advanced IDOR Vulnerability Testing Script

A comprehensive IDOR (Insecure Direct Object Reference) vulnerability testing script designed for ethical bug bounty hunting and security research.

## Features

### Core IDOR Testing
- **Standard IDOR Detection**: Tests for common IDOR vulnerabilities in URL parameters and paths
- **Parameter Pollution**: Advanced techniques to bypass access controls
- **HTTP Method Switching**: Tests different HTTP methods for IDOR
- **API Version Manipulation**: Tests older API versions that might have weaker controls
- **JWT Token Manipulation**: Tests for IDOR via JWT payload manipulation
- **Race Condition Testing**: Detects timing-based IDOR vulnerabilities
- **GraphQL IDOR Testing**: Specialized testing for GraphQL endpoints
- **Mass Assignment**: Tests for IDOR via object property injection

### High-Value Vulnerability Testing
- **Privileged Endpoints**: Tests admin, management, and system endpoints
- **Batch Operations**: Tests bulk operations that often process multiple resources
- **Webhook Endpoints**: Tests webhook and callback endpoints for sensitive data
- **File Operations**: Tests file upload/download endpoints for document access
- **Admin Functions**: Tests administrative functions with elevated privileges
- **Payment Endpoints**: Tests billing and payment systems for financial data
- **API Key Endpoints**: Tests credential and token management endpoints
- **OAuth Endpoints**: Tests authentication and authorization endpoints

### Advanced Techniques
- **Sequential ID Testing**: Tests predictable ID sequences (1-20, 100-120, etc.)
- **Common High-Value IDs**: Tests admin, root, system, and other privileged IDs
- **Header Manipulation**: Tests for IDOR via custom HTTP headers
- **JSON Path Traversal**: Tests nested JSON structures for IDOR
- **Advanced Parameter Techniques**: URL encoding, case manipulation, and more

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd Cylinder

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Test a target URL for IDOR vulnerabilities
python cylinder.py -u https://target.com

# Test with authentication cookies
python cylinder.py -u https://target.com -c "session=abc123; user_id=123"

# Test with custom headers
python cylinder.py -u https://target.com -H "Authorization: Bearer token123" -H "X-API-Key: key123"
```

### High-Value Testing

```bash
# Enable all high-value tests (recommended for bug bounty hunting)
python cylinder.py -u https://target.com --all-high-value

# Test specific high-value areas
python cylinder.py -u https://target.com --privileged --payment --admin

# Test with sequential IDs and common high-value IDs
python cylinder.py -u https://target.com --sequential --common-ids
```

### Advanced Testing

```bash
# Test with JWT token manipulation
python cylinder.py -u https://target.com --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test GraphQL endpoints
python cylinder.py -u https://target.com --graphql

# Test with custom user IDs
python cylinder.py -u https://target.com -i "admin,root,system,user1,user2"

# Use proxy for testing
python cylinder.py -u https://target.com --proxy "http://127.0.0.1:8080"

# Save results to file
python cylinder.py -u https://target.com --output results.json
```

### Verbose Output

```bash
# Enable verbose output for detailed testing information
python cylinder.py -u https://target.com --verbose --all-high-value
```

## Command Line Options

### Basic Options
- `-u, --url`: Target URL (required)
- `-c, --cookies`: Cookies string (format: key1=value1; key2=value2)
- `-H, --headers`: Custom headers (can be used multiple times)
- `-i, --ids`: Comma-separated list of custom IDs to test
- `-v, --verbose`: Enable verbose output
- `-t, --timeout`: Request timeout in seconds (default: 10)
- `-p, --proxy`: Proxy URL (format: http://127.0.0.1:8080)
- `-o, --output`: Output file for results (JSON format)
- `--no-ssl-verify`: Disable SSL certificate verification
- `--threads`: Number of concurrent threads (default: 5)

### Advanced Options
- `--jwt`: JWT token to manipulate for testing
- `--graphql`: Enable GraphQL-specific IDOR testing

### High-Value Testing Options
- `--all-high-value`: Enable all high-value IDOR tests
- `--sequential`: Test sequential IDs (1-20, 100-120, 1000-1020)
- `--common-ids`: Test common high-value IDs (admin, root, system, etc.)
- `--privileged`: Test privileged endpoints (admin, management, etc.)
- `--batch`: Test batch operations for IDOR
- `--webhooks`: Test webhook endpoints for IDOR
- `--files`: Test file operations for IDOR
- `--admin`: Test admin functions for IDOR
- `--payment`: Test payment endpoints for IDOR
- `--api-keys`: Test API key endpoints for IDOR
- `--oauth`: Test OAuth endpoints for IDOR

## Output

The script provides detailed output including:

### Console Output
- Real-time progress with spinner
- Color-coded severity levels (CRITICAL, HIGH, MEDIUM)
- Summary of findings by severity
- Detailed vulnerability table

### JSON Output
When using `--output`, results are saved in JSON format:
```json
{
  "target": "https://target.com",
  "timestamp": "2024-01-01 12:00:00",
  "findings": [
    {
      "type": "IDOR",
      "url": "https://target.com/api/user/admin",
      "description": "Privileged endpoint test: /admin/ with ID admin",
      "status": 200,
      "severity": "CRITICAL",
      "response_sample": "..."
    }
  ]
}
```

## Severity Levels

- **CRITICAL**: Payment systems, admin functions, API keys, OAuth endpoints
- **HIGH**: Privileged endpoints, batch operations, webhooks, file operations
- **MEDIUM**: Standard IDOR vulnerabilities, parameter pollution, method switching

## Best Practices for Bug Bounty Hunting

1. **Start with High-Value Tests**: Use `--all-high-value` for maximum coverage
2. **Test Authenticated Endpoints**: Always test with valid authentication
3. **Use Sequential IDs**: Many applications use predictable ID sequences
4. **Test Admin Functions**: Admin endpoints often contain the most valuable data
5. **Check Payment Systems**: Financial data is highly valued by bug bounty programs
6. **Test File Operations**: Document access can lead to significant bounties
7. **Use Verbose Mode**: Detailed output helps understand the testing process
8. **Save Results**: Always save results for later analysis and reporting

## Legal and Ethical Use

This tool is designed for:
- **Authorized security testing** on systems you own or have permission to test
- **Bug bounty programs** where you have explicit authorization
- **Educational purposes** in controlled environments

**Do not use this tool for:**
- Unauthorized testing of systems you don't own
- Malicious attacks or data theft
- Testing production systems without permission

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- New testing techniques
- Bug fixes
- Performance improvements
- Documentation updates

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse of this tool. Always ensure you have proper authorization before testing any system.
