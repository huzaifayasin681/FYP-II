# xss_scanner/crawler/crawler_fixed.py
"""Fixed crawler with binary content handling."""

import asyncio
import logging
import re
from collections import deque
from typing import Set, List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from urllib.robotparser import RobotFileParser

import aiohttp
import requests
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Page

logger = logging.getLogger(__name__)


class CrawlerBase:
    """Base crawler with shared functionality."""
    
    def __init__(self, base_url: str, max_depth: int = 3, 
                 same_domain_only: bool = True,
                 respect_robots: bool = True,
                 url_patterns: Optional[List[str]] = None):
        self.base_url = base_url
        self.max_depth = max_depth
        self.same_domain_only = same_domain_only
        self.respect_robots = respect_robots
        self.url_patterns = url_patterns or []
        self.base_domain = urlparse(base_url).netloc
        self.visited_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.robot_parser = self._init_robot_parser() if respect_robots else None
        
        # Skip these extensions
        self.skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
            '.pdf', '.zip', '.rar', '.tar', '.gz', '.7z',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.exe', '.dmg', '.pkg', '.deb', '.rpm'
        }
    
    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped based on extension."""
        parsed = urlparse(url.lower())
        path = parsed.path
        
        # Check file extension
        for ext in self.skip_extensions:
            if path.endswith(ext):
                return True
        
        # Check if it's an image serving endpoint
        if 'image' in path or 'img' in path or 'photo' in path or 'picture' in path:
            if any(param in parsed.query.lower() for param in ['file=', 'filename=', 'path=']):
                return True
        
        return False
    
    def _init_robot_parser(self) -> Optional[RobotFileParser]:
        """Initialize robots.txt parser."""
        try:
            rp = RobotFileParser()
            rp.set_url(urljoin(self.base_url, '/robots.txt'))
            rp.read()
            return rp
        except Exception as e:
            logger.warning(f"Failed to parse robots.txt: {e}")
            return None
    
    def _should_crawl_url(self, url: str) -> bool:
        """Check if URL should be crawled based on filters."""
        # Skip binary content
        if self._should_skip_url(url):
            return False
            
        parsed = urlparse(url)
        
        # Check same domain
        if self.same_domain_only and parsed.netloc != self.base_domain:
            return False
        
        # Check robots.txt
        if self.robot_parser and not self.robot_parser.can_fetch("*", url):
            return False
        
        # Check URL patterns
        if self.url_patterns:
            if not any(re.match(pattern, url) for pattern in self.url_patterns):
                return False
        
        return True
    
    def _extract_forms(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Extract forms from HTML."""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        return forms


class Crawler(CrawlerBase):
    """Synchronous crawler using requests."""
    
    def __init__(self, *args, session: Optional[requests.Session] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'XSS-Scanner/1.0'
        })
    
    def crawl(self) -> Tuple[Set[str], List[Dict]]:
        """Perform synchronous crawl."""
        queue = deque([(self.base_url, 0)])
        
        while queue:
            url, depth = queue.popleft()
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
            
            if not self._should_crawl_url(url):
                continue
            
            logger.debug(f"Crawling: {url} (depth: {depth})")
            self.visited_urls.add(url)
            
            try:
                response = self.session.get(url, timeout=10)
                response.raise_for_status()
                
                # Check content type
                content_type = response.headers.get('content-type', '').lower()
                if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                    logger.debug(f"Skipping non-HTML content: {url} ({content_type})")
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                forms = self._extract_forms(soup, url)
                self.discovered_forms.extend(forms)
                
                # Extract links
                for link in soup.find_all(['a', 'link']):
                    href = link.get('href')
                    if href:
                        absolute_url = urljoin(url, href)
                        if absolute_url not in self.visited_urls:
                            queue.append((absolute_url, depth + 1))
                
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")
        
        return self.visited_urls, self.discovered_forms


class AsyncCrawler(CrawlerBase):
    """Asynchronous crawler using aiohttp."""
    
    def __init__(self, *args, max_concurrent: int = 10, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def _fetch_url(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch URL content asynchronously."""
        try:
            async with self.semaphore:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        # Check content type
                        content_type = response.headers.get('content-type', '').lower()
                        if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                            logger.debug(f"Skipping non-HTML content: {url} ({content_type})")
                            return None
                        
                        # Try to decode as text
                        try:
                            return await response.text()
                        except UnicodeDecodeError:
                            logger.debug(f"Cannot decode content as text: {url}")
                            return None
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
        return None
    
    async def crawl(self) -> Tuple[Set[str], List[Dict]]:
        """Perform asynchronous crawl."""
        async with aiohttp.ClientSession(headers={'User-Agent': 'XSS-Scanner/1.0'}) as session:
            queue = asyncio.Queue()
            await queue.put((self.base_url, 0))
            
            tasks = []
            
            async def process_queue():
                while True:
                    try:
                        url, depth = await asyncio.wait_for(queue.get(), timeout=1)
                    except asyncio.TimeoutError:
                        break
                    
                    if url in self.visited_urls or depth > self.max_depth:
                        continue
                    
                    if not self._should_crawl_url(url):
                        continue
                    
                    logger.debug(f"Async crawling: {url} (depth: {depth})")
                    self.visited_urls.add(url)
                    
                    content = await self._fetch_url(session, url)
                    if content:
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Extract forms
                        forms = self._extract_forms(soup, url)
                        self.discovered_forms.extend(forms)
                        
                        # Extract links
                        for link in soup.find_all(['a', 'link']):
                            href = link.get('href')
                            if href:
                                absolute_url = urljoin(url, href)
                                if absolute_url not in self.visited_urls:
                                    await queue.put((absolute_url, depth + 1))
            
            # Run multiple workers
            workers = [asyncio.create_task(process_queue()) 
                      for _ in range(min(self.max_concurrent, 5))]
            
            await asyncio.gather(*workers, return_exceptions=True)
            
        return self.visited_urls, self.discovered_forms


class PlaywrightCrawler(CrawlerBase):
    """Crawler using Playwright for JavaScript-rendered content."""
    
    async def crawl(self) -> Tuple[Set[str], List[Dict]]:
        """Perform crawl with headless browser."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            queue = deque([(self.base_url, 0)])
            
            while queue:
                url, depth = queue.popleft()
                
                if url in self.visited_urls or depth > self.max_depth:
                    continue
                
                if not self._should_crawl_url(url):
                    continue
                
                logger.debug(f"Playwright crawling: {url} (depth: {depth})")
                self.visited_urls.add(url)
                
                try:
                    response = await page.goto(url, wait_until='networkidle')
                    
                    # Check content type
                    if response:
                        content_type = response.headers.get('content-type', '').lower()
                        if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                            logger.debug(f"Skipping non-HTML content: {url}")
                            continue
                    
                    # Wait for dynamic content
                    await page.wait_for_timeout(2000)
                    
                    # Get rendered HTML
                    content = await page.content()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Extract forms
                    forms = self._extract_forms(soup, url)
                    self.discovered_forms.extend(forms)
                    
                    # Extract links (including JS-generated)
                    links = await page.evaluate('''
                        () => Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href)
                    ''')
                    
                    for link in links:
                        absolute_url = urljoin(url, link)
                        if absolute_url not in self.visited_urls:
                            queue.append((absolute_url, depth + 1))
                    
                except Exception as e:
                    logger.error(f"Error with Playwright crawl {url}: {e}")
            
            await browser.close()
        
        return self.visited_urls, self.discovered_forms