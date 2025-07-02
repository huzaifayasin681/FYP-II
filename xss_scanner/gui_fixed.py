"""Improved GUI for XSS Scanner with error handling."""

from multiprocessing import parent_process
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import queue
from datetime import datetime
import webbrowser
from pathlib import Path

class ImprovedXSScannerGUI:
    """Improved GUI for XSS Scanner."""
    
    def __init__(self,parent):
        self.root = parent
        
        
        # Variables
        self.target_url = tk.StringVar(value="http://testphp.vulnweb.com")
        self.scan_depth = tk.IntVar(value=2)
        self.max_urls = tk.IntVar(value=10)
        self.scanning = False
        
        self._create_widgets()
        
    def _create_widgets(self):
        """Create GUI widgets."""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scan tab
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text='Scanner')
        self._create_scan_tab(scan_frame)
        
        # Results tab
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text='Results')
        self._create_results_tab(results_frame)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to scan")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _create_scan_tab(self, parent):
        """Create scan configuration tab."""
        # Configuration frame
        config_frame = ttk.LabelFrame(parent, text="Scan Configuration", padding=10)
        config_frame.pack(fill='x', padx=10, pady=5)
        
        # Target URL
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        url_entry = ttk.Entry(config_frame, textvariable=self.target_url, width=50)
        url_entry.grid(row=0, column=1, pady=5, padx=5)
        
        # Common targets dropdown
        ttk.Label(config_frame, text="Or select:").grid(row=0, column=2, padx=5)
        targets = [
            "http://testphp.vulnweb.com",
            "http://demo.testfire.net",
            "https://example.com",
            "Custom URL"
        ]
        target_combo = ttk.Combobox(config_frame, values=targets, width=25)
        target_combo.grid(row=0, column=3, padx=5)
        target_combo.bind('<<ComboboxSelected>>', lambda e: self.target_url.set(target_combo.get()) if target_combo.get() != "Custom URL" else None)
        
        # Scan depth
        ttk.Label(config_frame, text="Crawl Depth:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(config_frame, from_=1, to=5, textvariable=self.scan_depth, width=10).grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Max URLs
        ttk.Label(config_frame, text="Max URLs to test:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(config_frame, from_=5, to=100, textvariable=self.max_urls, width=10, increment=5).grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="🚀 Start Scan", command=self._start_scan)
        self.scan_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="⏹ Stop", command=self._stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="📊 View Last Report", command=self._view_report).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🗑 Clear Output", command=self._clear_output).pack(side='left', padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=10, pady=5)
        
        # Output area
        output_frame = ttk.LabelFrame(parent, text="Scan Output", padding=5)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        self.output_text.pack(fill='both', expand=True)
        
        # Configure tags for colored output
        self.output_text.tag_config('INFO', foreground='blue')
        self.output_text.tag_config('SUCCESS', foreground='green')
        self.output_text.tag_config('WARNING', foreground='orange')
        self.output_text.tag_config('ERROR', foreground='red')
        self.output_text.tag_config('VULN', foreground='red', font=('Arial', 10, 'bold'))
        
    def _create_results_tab(self, parent):
        """Create results display tab."""
        # Summary frame
        summary_frame = ttk.LabelFrame(parent, text="Last Scan Summary", padding=10)
        summary_frame.pack(fill='x', padx=10, pady=5)
        
        self.summary_text = tk.Text(summary_frame, height=8, wrap='word')
        self.summary_text.pack(fill='x')
        
        # Vulnerabilities frame
        vuln_frame = ttk.LabelFrame(parent, text="Detected Vulnerabilities", padding=10)
        vuln_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create treeview
        columns = ('Severity', 'Type', 'URL', 'Injection Point')
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=columns, show='tree headings', height=15)
        
        # Configure columns
        self.vuln_tree.heading('#0', text='#')
        self.vuln_tree.column('#0', width=40)
        
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(vuln_frame, orient='vertical', command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
    def _log(self, message, tag='INFO'):
        """Log message to output with color."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.output_text.insert('end', f"[{timestamp}] {message}\n", tag)
        self.output_text.see('end')
        self.root.update()
        
    def _start_scan(self):
        """Start the scan."""
        if not self.target_url.get():
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress")
            return
            
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_var.set(0)
        
        # Clear previous output
        self._clear_output()
        self._log(f"🎯 Starting scan of {self.target_url.get()}", 'INFO')
        
        # Run scan in thread
        thread = threading.Thread(target=self._run_scan)
        thread.daemon = True
        thread.start()
        
    def _run_scan(self):
        """Run the actual scan."""
        try:
            from crawler.crawler import Crawler
            from injector.injector import Injector
            from analyzer.analyzer import XSSAnalyzer
            from report.reporter import HTMLReporter
            
            # Phase 1: Crawling
            self._update_status("Phase 1: Crawling...")
            self._log("🕷️ Starting crawl phase...", 'INFO')
            
            crawler = Crawler(self.target_url.get(), max_depth=self.scan_depth.get())
            urls, forms = crawler.crawl()
            
            self._log(f"✅ Found {len(urls)} URLs and {len(forms)} forms", 'SUCCESS')
            self.progress_var.set(30)
            
            # Limit URLs for testing
            test_urls = list(urls)[:self.max_urls.get()]
            test_forms = forms[:5]
            
            # Phase 2: Injection
            self._update_status("Phase 2: Injecting payloads...")
            self._log(f"💉 Testing {len(test_urls)} URLs and {len(test_forms)} forms...", 'INFO')
            
            injector = Injector()
            # Use limited payloads for GUI demo
            injector.payload_manager.payloads = injector.payload_manager.payloads[:5]
            
            results = []
            total_injections = len(test_urls) * len(injector.payload_manager.payloads)
            
            for i, result in enumerate(injector.inject(test_urls, test_forms)):
                results.append(result)
                progress = 30 + (40 * (i / total_injections))
                self.progress_var.set(progress)
                
            self._log(f"✅ Completed {len(results)} injections", 'SUCCESS')
            
            # Phase 3: Analysis
            self._update_status("Phase 3: Analyzing results...")
            self._log("🔬 Analyzing responses for vulnerabilities...", 'INFO')
            
            analyzer = XSSAnalyzer()
            for result in results:
                analyzer.analyze(result)
                
            self.progress_var.set(90)
            
            # Get results
            summary = analyzer.get_summary()
            self._display_results(summary, analyzer.vulnerabilities)
            
            # Generate report
            self._generate_report(summary, analyzer.vulnerabilities, test_urls, test_forms)
            
            self.progress_var.set(100)
            self._update_status("Scan complete!")
            self._log("✅ Scan completed successfully!", 'SUCCESS')
            
        except Exception as e:
            self._log(f"❌ Error during scan: {str(e)}", 'ERROR')
            self._update_status("Scan failed")
            
        finally:
            self.scanning = False
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')
            
    def _display_results(self, summary, vulnerabilities):
        """Display scan results."""
        # Update summary
        summary_text = f"""
Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Total vulnerabilities found: {summary['total_vulnerabilities']}
Confirmed vulnerabilities: {summary['confirmed_vulnerabilities']}

Severity breakdown:
  • High: {summary['severity_breakdown']['HIGH']}
  • Medium: {summary['severity_breakdown']['MEDIUM']}
  • Low: {summary['severity_breakdown']['LOW']}

Unique injection points: {summary['unique_injection_points']}
        """
        
        self.summary_text.delete('1.0', 'end')
        self.summary_text.insert('1.0', summary_text)
        
        # Clear vulnerability tree
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
            
        # Add vulnerabilities to tree
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'LOW')
            vuln_type = vuln.get('type', 'Unknown')
            url = vuln.get('url', '')[:50] + '...' if len(vuln.get('url', '')) > 50 else vuln.get('url', '')
            injection_point = vuln.get('injection_point', 'Unknown')
            
            # Add to tree with color based on severity
            item = self.vuln_tree.insert('', 'end', text=str(i), 
                                        values=(severity, vuln_type, url, injection_point))
            
            # Color based on severity
            if severity == 'HIGH':
                self.vuln_tree.item(item, tags=('high',))
            elif severity == 'MEDIUM':
                self.vuln_tree.item(item, tags=('medium',))
                
        # Configure tags
        self.vuln_tree.tag_configure('high', foreground='red')
        self.vuln_tree.tag_configure('medium', foreground='orange')
        
        # Log summary
        if summary['total_vulnerabilities'] > 0:
            self._log(f"\n⚠️ Found {summary['total_vulnerabilities']} vulnerabilities!", 'VULN')
            for vuln in vulnerabilities[:3]:  # Show first 3
                self._log(f"  • {vuln['severity']} - {vuln['type']} at {vuln['injection_point']}", 'WARNING')
                
    def _generate_report(self, summary, vulnerabilities, urls, forms):
        """Generate HTML report."""
        try:
            from pathlib import Path
            from report.reporter import HTMLReporter
            
            output_dir = Path("scan_results")
            output_dir.mkdir(exist_ok=True)
            
            scan_results = {
                'scan_info': {
                    'target_url': self.target_url.get(),
                    'start_time': datetime.now().isoformat(),
                    'duration': '30 seconds',
                    'urls_scanned': len(urls),
                    'forms_scanned': len(forms)
                },
                'summary': summary,
                'vulnerabilities': vulnerabilities,
                'csp_bypasses': []
            }
            
            reporter = HTMLReporter()
            if reporter.generate(scan_results, output_dir):
                self._log(f"📄 Report saved to: scan_results/xss_scan_report.html", 'SUCCESS')
                self.last_report = output_dir / 'xss_scan_report.html'
                
        except Exception as e:
            self._log(f"Failed to generate report: {e}", 'ERROR')
            
    def _view_report(self):
        """Open the last generated report."""
        if hasattr(self, 'last_report') and self.last_report.exists():
            webbrowser.open(str(self.last_report))
        else:
            # Try to find any report
            report_path = Path("scan_results/xss_scan_report.html")
            if report_path.exists():
                webbrowser.open(str(report_path))
            else:
                messagebox.showinfo("Info", "No report found. Run a scan first.")
                
    def _stop_scan(self):
        """Stop the current scan."""
        self.scanning = False
        self._log("⏹ Scan stopped by user", 'WARNING')
        self._update_status("Scan stopped")
        
    def _clear_output(self):
        """Clear the output text."""
        self.output_text.delete('1.0', 'end')
        
    def _update_status(self, message):
        """Update status bar."""
        self.status_var.set(message)
        self.root.update()
        
    def run(self):
        """Start the GUI."""
        

if __name__ == "__main__":
    app = ImprovedXSScannerGUI()
    app.run()