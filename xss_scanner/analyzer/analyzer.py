# xss_scanner/analyzer/analyzer.py
"""Response and DOM analysis for XSS detection."""

import re
import logging
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import unquote

from bs4 import BeautifulSoup, Comment

logger = logging.getLogger(__name__)


class VulnerabilityContext(Enum):
    """Context where XSS payload appears."""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_COMMENT = "html_comment"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URL = "url"
    JSON = "json"


class XSSType(Enum):
    """Types of XSS vulnerabilities."""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"


class XSSAnalyzer:
    """Analyzes responses for XSS vulnerabilities."""
    
    def __init__(self):
        self.vulnerabilities: List[Dict] = []
        self.csp_bypasses: List[Dict] = []
        
        # Patterns for detecting successful XSS
        self.xss_patterns = [
            re.compile(r'<script[^>]*>.*?alert\s*\(.*?\).*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'on\w+\s*=\s*["\']?alert\s*\(.*?\)', re.IGNORECASE),
            re.compile(r'javascript:\s*alert\s*\(.*?\)', re.IGNORECASE),
            re.compile(r'<img[^>]+onerror\s*=\s*["\']?alert\s*\(.*?\)', re.IGNORECASE),
            re.compile(r'<svg[^>]+onload\s*=\s*["\']?alert\s*\(.*?\)', re.IGNORECASE),
        ]
        
        # DOM XSS sink patterns
        self.dom_sinks = [
            'eval(',
            'innerHTML',
            'outerHTML',
            'document.write',
            'document.writeln',
            'insertAdjacentHTML',
            'onevent',
            'setTimeout(',
            'setInterval(',
            'Function(',
            'location',
            'location.href',
            'location.replace',
            'location.assign',
            'window.open',
            'document.URL',
            'document.documentURI',
            'document.URLUnencoded',
            'document.baseURI',
            'document.referrer'
        ]
    
    def analyze(self, injection_result: Dict) -> List[Dict]:
        """Analyze injection result for vulnerabilities."""
        vulnerabilities = []
        
        injection = injection_result['injection']
        response_text = injection_result['response_text']
        response_headers = injection_result['response_headers']
        
        # Check for reflected XSS
        reflected_vulns = self._check_reflected_xss(injection, response_text)
        vulnerabilities.extend(reflected_vulns)
        
        # Check for DOM XSS
        dom_vulns = self._check_dom_xss(injection, response_text)
        vulnerabilities.extend(dom_vulns)
        
        # Analyze CSP
        csp_analysis = self._analyze_csp(response_headers)
        if csp_analysis:
            self.csp_bypasses.append(csp_analysis)
        
        # Context classification
        for vuln in vulnerabilities:
            vuln['context'] = self._classify_context(
                vuln['payload'],
                response_text,
                vuln.get('location', 0)
            )
            vuln['severity'] = self._calculate_severity(vuln)
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    def _check_reflected_xss(self, injection: Dict, response_text: str) -> List[Dict]:
        """Check for reflected XSS vulnerabilities."""
        vulnerabilities = []
        payload = injection['payload']
        
        # Direct payload reflection
        if payload in response_text:
            # Check if payload is executed
            for pattern in self.xss_patterns:
                if pattern.search(response_text):
                    location = response_text.find(payload)
                    vulnerabilities.append({
                        'type': XSSType.REFLECTED.value,
                        'injection_point': injection['injection_point'],
                        'payload': payload,
                        'url': injection['url'],
                        'method': injection['method'],
                        'location': location,
                        'evidence': self._extract_evidence(response_text, location),
                        'confirmed': True
                    })
                    break
            else:
                # Payload reflected but not executed
                location = response_text.find(payload)
                vulnerabilities.append({
                    'type': XSSType.REFLECTED.value,
                    'injection_point': injection['injection_point'],
                    'payload': payload,
                    'url': injection['url'],
                    'method': injection['method'],
                    'location': location,
                    'evidence': self._extract_evidence(response_text, location),
                    'confirmed': False
                })
        
        # Check for decoded/encoded variations
        decoded_payload = unquote(payload)
        if decoded_payload != payload and decoded_payload in response_text:
            location = response_text.find(decoded_payload)
            vulnerabilities.append({
                'type': XSSType.REFLECTED.value,
                'injection_point': injection['injection_point'],
                'payload': payload,
                'decoded_payload': decoded_payload,
                'url': injection['url'],
                'method': injection['method'],
                'location': location,
                'evidence': self._extract_evidence(response_text, location),
                'confirmed': False
            })
        
        return vulnerabilities
    
    def _check_dom_xss(self, injection: Dict, response_text: str) -> List[Dict]:
        """Check for DOM-based XSS vulnerabilities."""
        vulnerabilities = []
        
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            scripts = soup.find_all('script')
            
            for script in scripts:
                if script.string:
                    script_content = script.string
                    
                    # Check for dangerous sinks with user input
                    for sink in self.dom_sinks:
                        if sink in script_content:
                            # Look for patterns suggesting user input flows to sink
                            patterns = [
                                rf'{sink}.*?["\'].*?{re.escape(injection["payload"])}',
                                rf'{sink}.*?location\.(search|hash|href)',
                                rf'{sink}.*?document\.(URL|referrer|location)',
                                rf'{sink}.*?window\.name'
                            ]
                            
                            for pattern in patterns:
                                if re.search(pattern, script_content, re.IGNORECASE | re.DOTALL):
                                    vulnerabilities.append({
                                        'type': XSSType.DOM.value,
                                        'injection_point': injection['injection_point'],
                                        'payload': injection['payload'],
                                        'url': injection['url'],
                                        'method': injection['method'],
                                        'sink': sink,
                                        'evidence': script_content[:200],
                                        'confirmed': False
                                    })
                                    break
        
        except Exception as e:
            logger.error(f"DOM XSS analysis failed: {e}")
        
        return vulnerabilities
    
    def _classify_context(self, payload: str, response_text: str, location: int) -> str:
        """Classify the context where payload appears."""
        try:
            # Get surrounding context
            start = max(0, location - 100)
            end = min(len(response_text), location + len(payload) + 100)
            context_text = response_text[start:end]
            
            # Check if in script tag
            if re.search(r'<script[^>]*>.*?' + re.escape(payload), context_text, re.IGNORECASE | re.DOTALL):
                return VulnerabilityContext.JAVASCRIPT.value
            
            # Check if in style tag or attribute
            if re.search(r'<style[^>]*>.*?' + re.escape(payload), context_text, re.IGNORECASE | re.DOTALL):
                return VulnerabilityContext.CSS.value
            
            # Check if in HTML attribute
            if re.search(r'<[^>]+\s+\w+=["\']?[^"\']*?' + re.escape(payload), context_text, re.IGNORECASE):
                return VulnerabilityContext.HTML_ATTRIBUTE.value
            
            # Check if in HTML comment
            if re.search(r'<!--.*?' + re.escape(payload) + '.*?-->', context_text, re.IGNORECASE | re.DOTALL):
                return VulnerabilityContext.HTML_COMMENT.value
            
            # Check if in URL
            if re.search(r'(href|src|action)=["\']?[^"\']*?' + re.escape(payload), context_text, re.IGNORECASE):
                return VulnerabilityContext.URL.value
            
            # Default to HTML body
            return VulnerabilityContext.HTML_BODY.value
            
        except Exception as e:
            logger.error(f"Context classification failed: {e}")
            return VulnerabilityContext.HTML_BODY.value
    
    def _calculate_severity(self, vulnerability: Dict) -> str:
        """Calculate vulnerability severity."""
        # High severity: Confirmed execution in JS context
        if vulnerability.get('confirmed') and vulnerability.get('context') == VulnerabilityContext.JAVASCRIPT.value:
            return 'HIGH'
        
        # High severity: Confirmed execution in HTML
        if vulnerability.get('confirmed'):
            return 'HIGH'
        
        # Medium severity: Reflected but not confirmed
        if vulnerability['type'] == XSSType.REFLECTED.value:
            return 'MEDIUM'
        
        # Medium severity: DOM XSS with dangerous sink
        if vulnerability['type'] == XSSType.DOM.value and vulnerability.get('sink') in ['eval', 'innerHTML', 'document.write']:
            return 'MEDIUM'
        
        # Low severity: Other cases
        return 'LOW'
    
    def _extract_evidence(self, response_text: str, location: int, context_size: int = 100) -> str:
        """Extract evidence around vulnerability location."""
        start = max(0, location - context_size)
        end = min(len(response_text), location + context_size)
        return response_text[start:end]
    
    def _analyze_csp(self, headers: Dict) -> Optional[Dict]:
        """Analyze Content Security Policy for bypasses."""
        csp_header = headers.get('Content-Security-Policy', headers.get('content-security-policy', ''))
        
        if not csp_header:
            return None
        
        bypasses = []
        
        # Check for unsafe directives
        unsafe_patterns = [
            (r'unsafe-inline', 'Allows inline scripts'),
            (r'unsafe-eval', 'Allows eval() and similar functions'),
            (r'data:', 'Allows data: URIs which can contain scripts'),
            (r'\*', 'Wildcard allows any source'),
            (r'http:', 'Allows insecure HTTP sources'),
        ]
        
        for pattern, description in unsafe_patterns:
            if re.search(pattern, csp_header, re.IGNORECASE):
                bypasses.append({
                    'pattern': pattern,
                    'description': description
                })
        
        # Check for missing directives
        important_directives = ['script-src', 'object-src', 'base-uri']
        for directive in important_directives:
            if directive not in csp_header:
                bypasses.append({
                    'missing_directive': directive,
                    'description': f'Missing {directive} directive'
                })
        
        if bypasses:
            return {
                'csp_header': csp_header,
                'bypasses': bypasses
            }
        
        return None
    
    def get_summary(self) -> Dict:
        """Get analysis summary."""
        confirmed_vulns = [v for v in self.vulnerabilities if v.get('confirmed')]
        
        severity_counts = {
            'HIGH': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH']),
            'MEDIUM': len([v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']),
            'LOW': len([v for v in self.vulnerabilities if v.get('severity') == 'LOW'])
        }
        
        context_counts = {}
        for context in VulnerabilityContext:
            count = len([v for v in self.vulnerabilities if v.get('context') == context.value])
            if count > 0:
                context_counts[context.value] = count
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'confirmed_vulnerabilities': len(confirmed_vulns),
            'severity_breakdown': severity_counts,
            'context_breakdown': context_counts,
            'csp_bypasses': len(self.csp_bypasses),
            'unique_injection_points': len(set(v['injection_point'] for v in self.vulnerabilities))
        }