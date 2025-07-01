# xss_scanner/injector/injector_fixed.py
"""Fixed XSS payload injection engine with binary content handling."""

import asyncio
import json
import logging
import time
import urllib.parse
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import aiohttp
import requests

logger = logging.getLogger(__name__)


class PayloadManager:
    """Manages XSS payloads and mutations."""
    
    def __init__(self, payload_file: str = None):
        self.payloads = self._load_payloads(payload_file)
        self.mutations = {
            'html_entity': self._html_entity_encode,
            'url_encode': self._url_encode,
            'double_encode': self._double_encode,
            'unicode': self._unicode_encode
        }
    
    def _load_payloads(self, payload_file: str) -> List[str]:
        """Load payloads from file."""
        if not payload_file:
            # Default payloads
            return [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '<iframe src="javascript:alert(1)">',
                '"><script>alert(1)</script>',
                "';alert(1);//",
                '${alert(1)}',
                '{{constructor.constructor("alert(1)")()}}',
            ]
        
        try:
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to load payload file: {e}")
            return []
    
    def _html_entity_encode(self, payload: str) -> str:
        """HTML entity encode payload."""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload."""
        return urllib.parse.quote(payload)
    
    def _double_encode(self, payload: str) -> str:
        """Double URL encode payload."""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def get_mutated_payloads(self, base_payload: str) -> List[Tuple[str, str]]:
        """Get all mutations of a payload."""
        mutations = [(base_payload, 'original')]
        for name, func in self.mutations.items():
            try:
                mutated = func(base_payload)
                mutations.append((mutated, name))
            except Exception as e:
                logger.debug(f"Mutation {name} failed: {e}")
        return mutations


class InjectorBase:
    """Base injector with shared functionality."""
    
    def __init__(self, payloads: Optional[List[str]] = None,
                 payload_file: Optional[str] = None,
                 max_retries: int = 3,
                 retry_delay: int = 1):
        self.payload_manager = PayloadManager(payload_file)
        if payloads:
            self.payload_manager.payloads.extend(payloads)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.results: List[Dict] = []
        
        # Skip these URLs for injection
        self.skip_patterns = [
            'showimage.php',
            'download.php',
            'getfile.php',
            'image.php',
            'file.php',
            '.jpg', '.jpeg', '.png', '.gif', '.pdf',
            '.zip', '.rar', '.exe', '.doc', '.mp4'
        ]
    
    def _should_skip_injection(self, url: str) -> bool:
        """Check if URL should be skipped for injection."""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in self.skip_patterns)
    
    def _inject_url_params(self, url: str, payload: str) -> List[Dict]:
        """Inject payload into URL parameters."""
        if self._should_skip_injection(url):
            return []
            
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        injections = []
        
        for param in params:
            # Create new params with injected payload
            new_params = params.copy()
            new_params[param] = [payload]
            
            # Rebuild URL
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            
            injections.append({
                'url': new_url,
                'method': 'GET',
                'injection_point': f'URL param: {param}',
                'payload': payload
            })
        
        return injections
    
    def _inject_form_data(self, form: Dict, payload: str) -> List[Dict]:
        """Inject payload into form fields."""
        if self._should_skip_injection(form.get('action', '')):
            return []
            
        injections = []
        
        for input_field in form['inputs']:
            if input_field['type'] not in ['submit', 'button', 'image']:
                data = {}
                
                # Fill form with payload in target field
                for field in form['inputs']:
                    if field['name'] == input_field['name']:
                        data[field['name']] = payload
                    else:
                        data[field['name']] = field['value'] or 'test'
                
                injections.append({
                    'url': form['action'],
                    'method': form['method'],
                    'data': data,
                    'injection_point': f'Form field: {input_field["name"]}',
                    'payload': payload
                })
        
        return injections
    
    def _inject_headers(self, url: str, payload: str) -> List[Dict]:
        """Inject payload into headers."""
        if self._should_skip_injection(url):
            return []
            
        headers_to_test = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Original-URL',
            'X-Rewrite-URL'
        ]
        
        injections = []
        for header in headers_to_test:
            injections.append({
                'url': url,
                'method': 'GET',
                'headers': {header: payload},
                'injection_point': f'Header: {header}',
                'payload': payload
            })
        
        return injections
    
    def _inject_json_body(self, url: str, payload: str) -> List[Dict]:
        """Inject payload into JSON body."""
        if self._should_skip_injection(url):
            return []
            
        # Common JSON structures
        json_templates = [
            {'username': payload, 'password': 'test'},
            {'search': payload},
            {'comment': payload},
            {'data': payload}
        ]
        
        injections = []
        for template in json_templates:
            injections.append({
                'url': url,
                'method': 'POST',
                'json': template,
                'headers': {'Content-Type': 'application/json'},
                'injection_point': f'JSON field: {list(template.keys())[0]}',
                'payload': payload
            })
        
        return injections


class Injector(InjectorBase):
    """Synchronous payload injector."""
    
    def __init__(self, *args, session: Optional[requests.Session] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = session or requests.Session()
    
    def inject(self, urls: List[str], forms: List[Dict]) -> List[Dict]:
        """Perform synchronous injection."""
        all_injections = []
        
        # Filter out binary URLs
        urls = [url for url in urls if not self._should_skip_injection(url)]
        
        # Generate all injection points
        for payload in self.payload_manager.payloads:
            for mutated_payload, mutation_type in self.payload_manager.get_mutated_payloads(payload):
                # URL parameter injection
                for url in urls:
                    all_injections.extend(self._inject_url_params(url, mutated_payload))
                    all_injections.extend(self._inject_headers(url, mutated_payload))
                    all_injections.extend(self._inject_json_body(url, mutated_payload))
                
                # Form injection
                for form in forms:
                    all_injections.extend(self._inject_form_data(form, mutated_payload))
        
        # Execute injections
        for injection in all_injections:
            result = self._execute_injection(injection)
            if result:
                self.results.append(result)
        
        return self.results
    
    def _execute_injection(self, injection: Dict) -> Optional[Dict]:
        """Execute a single injection."""
        retries = 0
        
        while retries < self.max_retries:
            try:
                logger.debug(f"Injecting {injection['payload']} at {injection['injection_point']}")
                
                # Prepare request parameters
                kwargs = {
                    'timeout': 10,
                    'allow_redirects': True
                }
                
                if 'data' in injection:
                    kwargs['data'] = injection['data']
                if 'json' in injection:
                    kwargs['json'] = injection['json']
                if 'headers' in injection:
                    kwargs['headers'] = injection.get('headers', {})
                
                # Make request
                response = self.session.request(
                    injection['method'],
                    injection['url'],
                    **kwargs
                )
                
                # Check for rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', self.retry_delay))
                    logger.warning(f"Rate limited, waiting {retry_after}s")
                    time.sleep(retry_after)
                    retries += 1
                    continue
                
                # Check content type
                content_type = response.headers.get('content-type', '').lower()
                if 'text' not in content_type and 'json' not in content_type and 'xml' not in content_type:
                    logger.debug(f"Skipping non-text response: {content_type}")
                    return None
                
                return {
                    'injection': injection,
                    'status_code': response.status_code,
                    'response_text': response.text,
                    'response_headers': dict(response.headers),
                    'request_headers': dict(response.request.headers),
                    'mutation_type': injection.get('mutation_type', 'original')
                }
                
            except Exception as e:
                logger.error(f"Injection failed: {e}")
                retries += 1
                time.sleep(self.retry_delay * (2 ** retries))  # Exponential backoff
        
        return None


class AsyncInjector(InjectorBase):
    """Asynchronous payload injector."""
    
    def __init__(self, *args, max_concurrent: int = 20, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def inject(self, urls: List[str], forms: List[Dict]) -> List[Dict]:
        """Perform asynchronous injection."""
        all_injections = []
        
        # Filter out binary URLs
        urls = [url for url in urls if not self._should_skip_injection(url)]
        
        # Generate all injection points
        for payload in self.payload_manager.payloads:
            for mutated_payload, mutation_type in self.payload_manager.get_mutated_payloads(payload):
                # URL parameter injection
                for url in urls:
                    injections = self._inject_url_params(url, mutated_payload)
                    for inj in injections:
                        inj['mutation_type'] = mutation_type
                    all_injections.extend(injections)
                    
                    injections = self._inject_headers(url, mutated_payload)
                    for inj in injections:
                        inj['mutation_type'] = mutation_type
                    all_injections.extend(injections)
                    
                    injections = self._inject_json_body(url, mutated_payload)
                    for inj in injections:
                        inj['mutation_type'] = mutation_type
                    all_injections.extend(injections)
                
                # Form injection
                for form in forms:
                    injections = self._inject_form_data(form, mutated_payload)
                    for inj in injections:
                        inj['mutation_type'] = mutation_type
                    all_injections.extend(injections)
        
        # Execute injections concurrently
        async with aiohttp.ClientSession() as session:
            tasks = [self._execute_injection(session, injection) 
                    for injection in all_injections]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out failed results
            self.results = [r for r in results if r and not isinstance(r, Exception)]
        
        return self.results
    
    async def _execute_injection(self, session: aiohttp.ClientSession, 
                                injection: Dict) -> Optional[Dict]:
        """Execute a single injection asynchronously."""
        async with self.semaphore:
            retries = 0
            
            while retries < self.max_retries:
                try:
                    logger.debug(f"Async injecting {injection['payload']} at {injection['injection_point']}")
                    
                    # Prepare request parameters
                    kwargs = {
                        'timeout': aiohttp.ClientTimeout(total=10),
                        'allow_redirects': True
                    }
                    
                    if 'data' in injection:
                        kwargs['data'] = injection['data']
                    if 'json' in injection:
                        kwargs['json'] = injection['json']
                    if 'headers' in injection:
                        kwargs['headers'] = injection.get('headers', {})
                    
                    # Make request
                    async with session.request(
                        injection['method'],
                        injection['url'],
                        **kwargs
                    ) as response:
                        # Check for rate limiting
                        if response.status == 429:
                            retry_after = int(response.headers.get('Retry-After', self.retry_delay))
                            logger.warning(f"Rate limited, waiting {retry_after}s")
                            await asyncio.sleep(retry_after)
                            retries += 1
                            continue
                        
                        # Check content type
                        content_type = response.headers.get('content-type', '').lower()
                        if 'text' not in content_type and 'json' not in content_type and 'xml' not in content_type:
                            logger.debug(f"Skipping non-text response: {content_type}")
                            return None
                        
                        # Try to read as text, skip if binary
                        try:
                            text = await response.text()
                        except UnicodeDecodeError:
                            logger.debug(f"Cannot decode response as text, skipping")
                            return None
                        
                        return {
                            'injection': injection,
                            'status_code': response.status,
                            'response_text': text,
                            'response_headers': dict(response.headers),
                            'request_headers': dict(kwargs.get('headers', {})),
                            'mutation_type': injection.get('mutation_type', 'original')
                        }
                    
                except Exception as e:
                    logger.error(f"Async injection failed: {e}")
                    retries += 1
                    await asyncio.sleep(self.retry_delay * (2 ** retries))
            
            return None