# xss_scanner/cli/main.py
"""Command-line interface for XSS Scanner."""

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not available
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = ''

# Fix imports to use absolute imports when run as a script
try:
    from crawler.crawler import Crawler, AsyncCrawler, PlaywrightCrawler
    from injector.injector import Injector, AsyncInjector
    from analyzer.analyzer import XSSAnalyzer
    from auth.auth import AuthFactory
    from report.reporter import HTMLReporter, JSONReporter, CSVReporter
except ImportError:
    # Try relative imports if absolute imports fail
    from ..crawler.crawler import Crawler, AsyncCrawler, PlaywrightCrawler
    from ..injector.injector import Injector, AsyncInjector
    from ..analyzer.analyzer import XSSAnalyzer
    from ..auth.auth import AuthFactory
    from ..report.reporter import HTMLReporter, JSONReporter, CSVReporter

logger = logging.getLogger(__name__)


class CLIProgress:
    """Colorized progress indicator for CLI."""
    
    def __init__(self):
        self.start_time = time.time()
    
    def info(self, message: str):
        """Display info message."""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
    
    def success(self, message: str):
        """Display success message."""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
    
    def warning(self, message: str):
        """Display warning message."""
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
    
    def error(self, message: str):
        """Display error message."""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
    
    def progress(self, current: int, total: int, message: str = ""):
        """Display progress bar."""
        if total == 0:
            return
        
        percentage = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        elapsed = time.time() - self.start_time
        eta = (elapsed / current * total) - elapsed if current > 0 else 0
        
        print(f"\r{Fore.CYAN}Progress: |{bar}| {percentage:.1f}% - {message} (ETA: {eta:.0f}s){Style.RESET_ALL}", end='', flush=True)
        
        if current == total:
            print()  # New line when complete


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='xss_scanner',
        description='Production-grade XSS vulnerability scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  xss_scanner scan --target https://example.com
  
  # Deep crawl with custom payloads
  xss_scanner crawl --target https://example.com --depth 5
  xss_scanner scan --payloads custom_payloads.txt --format html
  
  # Authenticated scan
  xss_scanner scan --target https://example.com --login-config auth.json
  
  # Async scan with high concurrency
  xss_scanner scan --target https://example.com --async --concurrency 50
        """
    )
    
    # Global arguments
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--log-file', type=str, help='Save logs to file')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Crawl command
    crawl_parser = subparsers.add_parser('crawl', help='Crawl target to discover URLs and forms')
    crawl_parser.add_argument('--target', '-t', required=True, help='Target URL to crawl')
    crawl_parser.add_argument('--depth', '-D', type=int, default=3, help='Maximum crawl depth (default: 3)')
    crawl_parser.add_argument('--same-domain', action='store_true', default=True, help='Only crawl same domain')
    crawl_parser.add_argument('--respect-robots', action='store_true', default=True, help='Respect robots.txt')
    crawl_parser.add_argument('--url-pattern', action='append', help='URL patterns to include (regex)')
    crawl_parser.add_argument('--playwright', action='store_true', help='Use Playwright for JS rendering')
    crawl_parser.add_argument('--async', dest='use_async', action='store_true', help='Use async crawler')
    crawl_parser.add_argument('--output', '-o', type=str, help='Save crawl results to file')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform XSS vulnerability scan')
    scan_parser.add_argument('--target', '-t', required=True, help='Target URL to scan')
    scan_parser.add_argument('--depth', '-D', type=int, default=3, help='Maximum crawl depth (default: 3)')
    scan_parser.add_argument('--payloads', '-p', type=str, help='Custom payload file')
    scan_parser.add_argument('--format', '-f', choices=['html', 'json', 'csv'], default='html', help='Report format')
    scan_parser.add_argument('--output', '-o', type=str, default='reports', help='Output directory')
    scan_parser.add_argument('--async', dest='use_async', action='store_true', help='Use async scanner')
    scan_parser.add_argument('--concurrency', '-c', type=int, default=20, help='Max concurrent requests')
    scan_parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    scan_parser.add_argument('--login-config', type=str, help='Authentication config file (JSON)')
    scan_parser.add_argument('--urls-file', type=str, help='File containing URLs to scan')
    scan_parser.add_argument('--forms-file', type=str, help='File containing forms to scan')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report from scan results')
    report_parser.add_argument('--input', '-i', required=True, help='Scan results file (JSON)')
    report_parser.add_argument('--format', '-f', choices=['html', 'json', 'csv'], default='html', help='Report format')
    report_parser.add_argument('--output', '-o', type=str, default='reports', help='Output directory')
    
    return parser


def setup_logging(verbose: bool, debug: bool, log_file: Optional[str]):
    """Configure logging."""
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s' if debug else '%(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers
    )
    
    # Suppress noisy libraries unless in debug mode
    if not debug:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('aiohttp').setLevel(logging.WARNING)


def load_auth_config(config_file: str) -> Optional[Dict]:
    """Load authentication configuration."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load auth config: {e}")
        return None


def run_crawl_sync(args) -> Dict:
    """Run synchronous crawl."""
    progress = CLIProgress()
    progress.info("Using sync crawler")
    crawler = Crawler(
        args.target,
        max_depth=args.depth,
        same_domain_only=args.same_domain,
        respect_robots=args.respect_robots,
        url_patterns=args.url_pattern
    )
    urls, forms = crawler.crawl()
    return urls, forms


async def run_crawl_async(args) -> Dict:
    """Run asynchronous crawl."""
    progress = CLIProgress()
    
    if args.playwright:
        progress.info("Using Playwright crawler for JS rendering")
        crawler = PlaywrightCrawler(
            args.target,
            max_depth=args.depth,
            same_domain_only=args.same_domain,
            respect_robots=args.respect_robots,
            url_patterns=args.url_pattern
        )
        urls, forms = await crawler.crawl()
    else:
        progress.info("Using async crawler")
        crawler = AsyncCrawler(
            args.target,
            max_depth=args.depth,
            same_domain_only=args.same_domain,
            respect_robots=args.respect_robots,
            url_patterns=args.url_pattern
        )
        urls, forms = await crawler.crawl()
    
    return urls, forms


def run_crawl(args) -> Dict:
    """Run crawl command (handles both sync and async)."""
    progress = CLIProgress()
    progress.info(f"Starting crawl of {args.target}")
    
    # Run appropriate crawler
    if args.use_async or args.playwright:
        urls, forms = asyncio.run(run_crawl_async(args))
    else:
        urls, forms = run_crawl_sync(args)
    
    progress.success(f"Crawl complete! Found {len(urls)} URLs and {len(forms)} forms")
    
    results = {
        'target': args.target,
        'urls': list(urls),
        'forms': forms,
        'timestamp': datetime.now().isoformat()
    }
    
    # Save results if requested
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        progress.success(f"Results saved to {output_path}")
    
    return results


def run_scan_sync(args, urls: List[str], forms: List[Dict], session=None) -> List[Dict]:
    """Run synchronous scan."""
    injector = Injector(
        payload_file=args.payloads,
        session=session
    )
    return injector.inject(urls, forms)


async def run_scan_async(args, urls: List[str], forms: List[Dict]) -> List[Dict]:
    """Run asynchronous scan."""
    injector = AsyncInjector(
        payload_file=args.payloads,
        max_concurrent=args.concurrency
    )
    return await injector.inject(urls, forms)


def run_scan(args) -> Dict:
    """Run scan command (handles both sync and async)."""
    progress = CLIProgress()
    start_time = datetime.now()
    
    progress.info(f"Starting XSS scan of {args.target}")
    
    # Load URLs and forms
    if args.urls_file or args.forms_file:
        urls = []
        forms = []
        
        if args.urls_file:
            with open(args.urls_file) as f:
                urls = [line.strip() for line in f if line.strip()]
            progress.info(f"Loaded {len(urls)} URLs from file")
        
        if args.forms_file:
            with open(args.forms_file) as f:
                forms = json.load(f)
            progress.info(f"Loaded {len(forms)} forms from file")
    else:
        # Run crawler first
        progress.info("Starting crawl phase...")
        crawl_args = argparse.Namespace(
            target=args.target,
            depth=args.depth,
            same_domain=True,
            respect_robots=True,
            url_pattern=None,
            playwright=False,
            use_async=args.use_async,
            output=None
        )
        crawl_results = run_crawl(crawl_args)
        urls = crawl_results['urls']
        forms = crawl_results['forms']
    
    # Setup authentication if needed
    session = None
    if args.login_config:
        progress.info("Setting up authentication...")
        auth_config = load_auth_config(args.login_config)
        if auth_config:
            auth_handler = AuthFactory.create_from_config(auth_config)
            if auth_handler:
                import requests
                session = requests.Session()
                if auth_handler.authenticate(session):
                    progress.success("Authentication successful")
                else:
                    progress.error("Authentication failed")
                    return {}
    
    # Run injection
    progress.info("Starting injection phase...")
    
    if args.use_async:
        injection_results = asyncio.run(run_scan_async(args, urls, forms))
    else:
        injection_results = run_scan_sync(args, urls, forms, session)
    
    progress.info(f"Completed {len(injection_results)} injections")
    
    # Analyze results
    progress.info("Analyzing responses for vulnerabilities...")
    analyzer = XSSAnalyzer()
    
    for i, result in enumerate(injection_results):
        analyzer.analyze(result)
        progress.progress(i + 1, len(injection_results), "Analyzing responses")
    
    # Get summary
    summary = analyzer.get_summary()
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    progress.success(f"Scan complete! Found {summary['total_vulnerabilities']} vulnerabilities")
    
    # Prepare final results
    scan_results = {
        'scan_info': {
            'target_url': args.target,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': f"{duration:.2f} seconds",
            'urls_scanned': len(urls),
            'forms_scanned': len(forms),
            'payloads_used': len(injection_results) // (len(urls) + len(forms)) if urls or forms else 0
        },
        'summary': summary,
        'vulnerabilities': analyzer.vulnerabilities,
        'csp_bypasses': analyzer.csp_bypasses
    }
    
    # Generate report
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    progress.info(f"Generating {args.format.upper()} report...")
    
    if args.format == 'html':
        reporter = HTMLReporter()
    elif args.format == 'json':
        reporter = JSONReporter()
    else:
        reporter = CSVReporter()
    
    if reporter.generate(scan_results, output_dir):
        progress.success(f"Report saved to {output_dir}")
    
    # Save raw results for later analysis
    raw_results_file = output_dir / 'scan_results.json'
    with open(raw_results_file, 'w') as f:
        json.dump(scan_results, f, indent=2)
    
    return scan_results


def run_report(args):
    """Generate report from existing scan results."""
    progress = CLIProgress()
    
    # Load scan results
    try:
        with open(args.input, 'r') as f:
            scan_results = json.load(f)
        progress.info(f"Loaded scan results from {args.input}")
    except Exception as e:
        progress.error(f"Failed to load scan results: {e}")
        return
    
    # Generate report
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    progress.info(f"Generating {args.format.upper()} report...")
    
    if args.format == 'html':
        reporter = HTMLReporter()
    elif args.format == 'json':
        reporter = JSONReporter()
    else:
        reporter = CSVReporter()
    
    if reporter.generate(scan_results, output_dir):
        progress.success(f"Report saved to {output_dir}")
    else:
        progress.error("Failed to generate report")


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    setup_logging(args.verbose, args.debug, args.log_file)
    
    try:
        if args.command == 'crawl':
            run_crawl(args)
        elif args.command == 'scan':
            run_scan(args)
        elif args.command == 'report':
            run_report(args)
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        return 130
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())