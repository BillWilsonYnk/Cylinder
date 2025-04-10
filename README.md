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
