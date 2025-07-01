# xss_scanner/gui/app.py
"""Tkinter GUI for XSS Scanner."""

import asyncio
import json
import logging
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# from .crawler.crawler import Crawler, AsyncCrawler
from ..crawler.crawler import Crawler, AsyncCrawler
from ..injector import Injector, AsyncInjector
from ..analyzer import XSSAnalyzer
from ..auth import AuthFactory
from ..report import HTMLReporter, JSONReporter, CSVReporter

logger = logging.getLogger(__name__)


class XSSScannerGUI:
    """Main GUI application for XSS Scanner."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("XSS Scanner - Professional Edition")
        self.root.geometry("1000x700")
        
        # Set icon if available
        try:
            self.root.iconbitmap('icon.ico')
        except:
            pass
        
        # Variables
        self.target_url = tk.StringVar()
        self.crawl_depth = tk.IntVar(value=3)
        self.payload_file = tk.StringVar()
        self.auth_config_file = tk.StringVar()
        self.output_format = tk.StringVar(value='html')
        self.use_async = tk.BooleanVar(value=True)
        self.max_concurrent = tk.IntVar(value=20)
        
        # Threading
        self.scan_thread = None
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        
        # Create UI
        self._create_widgets()
        self._setup_logging()
        
        # Start queue processors
        self.root.after(100, self._process_queues)
    
    def _create_widgets(self):
        """Create all GUI widgets."""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scan tab
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text='Scan Configuration')
        self._create_scan_tab(scan_frame)
        
        # Results tab
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text='Results')
        self._create_results_tab(results_frame)
        
        # Logs tab
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text='Logs')
        self._create_logs_tab(logs_frame)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _create_scan_tab(self, parent):
        """Create scan configuration tab."""
        # Target URL
        target_frame = ttk.LabelFrame(parent, text="Target Configuration", padding=10)
        target_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(target_frame, text="Target URL:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(target_frame, textvariable=self.target_url, width=50).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Crawl Depth:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Spinbox(target_frame, from_=1, to=10, textvariable=self.crawl_depth, width=10).grid(row=1, column=1, sticky='w', padx=5, pady=5)
        
        # Payload configuration
        payload_frame = ttk.LabelFrame(parent, text="Payload Configuration", padding=10)
        payload_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(payload_frame, text="Payload File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(payload_frame, textvariable=self.payload_file, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(payload_frame, text="Browse", command=self._browse_payload_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Authentication
        auth_frame = ttk.LabelFrame(parent, text="Authentication (Optional)", padding=10)
        auth_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(auth_frame, text="Auth Config:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(auth_frame, textvariable=self.auth_config_file, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(auth_frame, text="Browse", command=self._browse_auth_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Advanced options
        advanced_frame = ttk.LabelFrame(parent, text="Advanced Options", padding=10)
        advanced_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(advanced_frame, text="Use Async Mode", variable=self.use_async).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        
        ttk.Label(advanced_frame, text="Max Concurrent:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Spinbox(advanced_frame, from_=1, to=100, textvariable=self.max_concurrent, width=10).grid(row=1, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(advanced_frame, text="Output Format:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        format_combo = ttk.Combobox(advanced_frame, textvariable=self.output_format, values=['html', 'json', 'csv'], state='readonly', width=10)
        format_combo.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=10, pady=20)
        
        self.start_button = ttk.Button(button_frame, text="Start Scan", command=self._start_scan, style='Accent.TButton')
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self._stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Generate Report", command=self._generate_report).pack(side='left', padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=10, pady=5)
        
        self.progress_label = ttk.Label(parent, text="")
        self.progress_label.pack()
    
    def _create_results_tab(self, parent):
        """Create results display tab."""
        # Summary frame
        summary_frame = ttk.LabelFrame(parent, text="Scan Summary", padding=10)
        summary_frame.pack(fill='x', padx=10, pady=5)
        
        self.summary_text = tk.Text(summary_frame, height=6, wrap='word')
        self.summary_text.pack(fill='both', expand=True)
        
        # Vulnerabilities tree
        vuln_frame = ttk.LabelFrame(parent, text="Vulnerabilities", padding=10)
        vuln_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create treeview with scrollbars
        tree_scroll_y = ttk.Scrollbar(vuln_frame)
        tree_scroll_y.pack(side='right', fill='y')
        
        tree_scroll_x = ttk.Scrollbar(vuln_frame, orient='horizontal')
        tree_scroll_x.pack(side='bottom', fill='x')
        
        self.vuln_tree = ttk.Treeview(vuln_frame, 
                                      yscrollcommand=tree_scroll_y.set,
                                      xscrollcommand=tree_scroll_x.set,
                                      columns=('Severity', 'Type', 'URL', 'Injection Point', 'Context'))
        
        tree_scroll_y.config(command=self.vuln_tree.yview)
        tree_scroll_x.config(command=self.vuln_tree.xview)
        
        # Configure columns
        self.vuln_tree.heading('#0', text='ID')
        self.vuln_tree.heading('Severity', text='Severity')
        self.vuln_tree.heading('Type', text='Type')
        self.vuln_tree.heading('URL', text='URL')
        self.vuln_tree.heading('Injection Point', text='Injection Point')
        self.vuln_tree.heading('Context', text='Context')
        
        self.vuln_tree.column('#0', width=50)
        self.vuln_tree.column('Severity', width=80)
        self.vuln_tree.column('Type', width=100)
        self.vuln_tree.column('URL', width=300)
        self.vuln_tree.column('Injection Point', width=150)
        self.vuln_tree.column('Context', width=100)
        
        self.vuln_tree.pack(fill='both', expand=True)
        
        # Double-click to view details
        self.vuln_tree.bind('<Double-Button-1>', self._show_vuln_details)
    
    def _create_logs_tab(self, parent):
        """Create logs display tab."""
        # Log text widget
        self.log_text = scrolledtext.ScrolledText(parent, wrap='word', height=20)
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Configure tags for colored output
        self.log_text.tag_config('INFO', foreground='blue')
        self.log_text.tag_config('WARNING', foreground='orange')
        self.log_text.tag_config('ERROR', foreground='red')
        self.log_text.tag_config('SUCCESS', foreground='green')
        
        # Control buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="Clear Logs", command=self._clear_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Save Logs", command=self._save_logs).pack(side='left', padx=5)
    
    def _setup_logging(self):
        """Setup logging to GUI."""
        class GUILogHandler(logging.Handler):
            def __init__(self, queue):
                super().__init__()
                self.queue = queue
            
            def emit(self, record):
                self.queue.put(record)
        
        # Add GUI handler
        gui_handler = GUILogHandler(self.log_queue)
        gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(gui_handler)
    
    def _process_queues(self):
        """Process log and progress queues."""
        # Process logs
        while not self.log_queue.empty():
            try:
                record = self.log_queue.get_nowait()
                msg = f"{record.asctime} - {record.levelname} - {record.message}\n"
                self.log_text.insert('end', msg, record.levelname)
                self.log_text.see('end')
            except queue.Empty:
                break
        
        # Process progress
        while not self.progress_queue.empty():
            try:
                progress_data = self.progress_queue.get_nowait()
                if 'progress' in progress_data:
                    self.progress_var.set(progress_data['progress'])
                if 'message' in progress_data:
                    self.progress_label.config(text=progress_data['message'])
                if 'status' in progress_data:
                    self.status_var.set(progress_data['status'])
            except queue.Empty:
                break
        
        # Schedule next check
        self.root.after(100, self._process_queues)
    
    def _browse_payload_file(self):
        """Browse for payload file."""
        filename = filedialog.askopenfilename(
            title="Select Payload File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.payload_file.set(filename)
    
    def _browse_auth_file(self):
        """Browse for auth config file."""
        filename = filedialog.askopenfilename(
            title="Select Auth Config File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.auth_config_file.set(filename)
    
    def _start_scan(self):
        """Start the scan in a separate thread."""
        if not self.target_url.get():
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        # Disable start button
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        
        # Clear previous results
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.summary_text.delete('1.0', 'end')
        
        # Start scan thread
        self.scan_thread = threading.Thread(target=self._run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _run_scan(self):
        """Run the actual scan."""
        try:
            # Update status
            self.progress_queue.put({'status': 'Starting scan...', 'progress': 0})
            
            # Create event loop for async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run scan
            self.scan_results = loop.run_until_complete(self._perform_scan())
            
            # Update UI with results
            self.root.after(0, self._display_results)
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.progress_queue.put({'status': f'Scan failed: {e}', 'progress': 0})
        finally:
            self.root.after(0, lambda: self.start_button.config(state='normal'))
            self.root.after(0, lambda: self.stop_button.config(state='disabled'))
    
    async def _perform_scan(self):
        """Perform the actual scanning logic."""
        start_time = datetime.now()
        
        # Phase 1: Crawling
        self.progress_queue.put({'status': 'Crawling target...', 'progress': 10})
        
        if self.use_async.get():
            crawler = AsyncCrawler(
                self.target_url.get(),
                max_depth=self.crawl_depth.get(),
                max_concurrent=self.max_concurrent.get()
            )
            urls, forms = await crawler.crawl()
        else:
            crawler = Crawler(
                self.target_url.get(),
                max_depth=self.crawl_depth.get()
            )
            urls, forms = crawler.crawl()
        
        self.progress_queue.put({
            'status': f'Found {len(urls)} URLs and {len(forms)} forms',
            'progress': 30
        })
        
        # Phase 2: Authentication (if configured)
        session = None
        if self.auth_config_file.get():
            self.progress_queue.put({'status': 'Setting up authentication...', 'progress': 35})
            try:
                with open(self.auth_config_file.get()) as f:
                    auth_config = json.load(f)
                auth_handler = AuthFactory.create_from_config(auth_config)
                if auth_handler:
                    import requests
                    session = requests.Session()
                    auth_handler.authenticate(session)
            except Exception as e:
                logger.error(f"Authentication setup failed: {e}")
        
        # Phase 3: Injection
        self.progress_queue.put({'status': 'Injecting payloads...', 'progress': 40})
        
        payload_file = self.payload_file.get() if self.payload_file.get() else None
        
        if self.use_async.get():
            injector = AsyncInjector(
                payload_file=payload_file,
                max_concurrent=self.max_concurrent.get()
            )
            injection_results = await injector.inject(list(urls), forms)
        else:
            injector = Injector(
                payload_file=payload_file,
                session=session
            )
            injection_results = injector.inject(list(urls), forms)
        
        # Phase 4: Analysis
        self.progress_queue.put({'status': 'Analyzing responses...', 'progress': 70})
        
        analyzer = XSSAnalyzer()
        for i, result in enumerate(injection_results):
            analyzer.analyze(result)
            progress = 70 + (i / len(injection_results)) * 20
            self.progress_queue.put({'progress': progress})
        
        # Complete
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        scan_results = {
            'scan_info': {
                'target_url': self.target_url.get(),
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': f"{duration:.2f} seconds",
                'urls_scanned': len(urls),
                'forms_scanned': len(forms)
            },
            'summary': analyzer.get_summary(),
            'vulnerabilities': analyzer.vulnerabilities,
            'csp_bypasses': analyzer.csp_bypasses
        }
        
        self.progress_queue.put({
            'status': f'Scan complete! Found {len(analyzer.vulnerabilities)} vulnerabilities',
            'progress': 100
        })
        
        return scan_results
    
    def _display_results(self):
        """Display scan results in GUI."""
        if not hasattr(self, 'scan_results'):
            return
        
        # Update summary
        summary = self.scan_results['summary']
        summary_text = f"""Total Vulnerabilities: {summary['total_vulnerabilities']}
Confirmed: {summary['confirmed_vulnerabilities']}

Severity Breakdown:
- High: {summary['severity_breakdown']['HIGH']}
- Medium: {summary['severity_breakdown']['MEDIUM']}
- Low: {summary['severity_breakdown']['LOW']}

Unique Injection Points: {summary['unique_injection_points']}
CSP Bypasses Found: {summary['csp_bypasses']}"""
        
        self.summary_text.delete('1.0', 'end')
        self.summary_text.insert('1.0', summary_text)
        
        # Update vulnerability tree
        for i, vuln in enumerate(self.scan_results['vulnerabilities'], 1):
            severity = vuln.get('severity', 'LOW')
            
            # Add color tags
            if severity == 'HIGH':
                tags = ('high',)
            elif severity == 'MEDIUM':
                tags = ('medium',)
            else:
                tags = ('low',)
            
            self.vuln_tree.insert('', 'end', 
                                 text=str(i),
                                 values=(
                                     severity,
                                     vuln.get('type', 'Unknown'),
                                     vuln.get('url', '')[:50] + '...',
                                     vuln.get('injection_point', 'Unknown'),
                                     vuln.get('context', 'Unknown')
                                 ),
                                 tags=tags)
        
        # Configure tag colors
        self.vuln_tree.tag_configure('high', foreground='red')
        self.vuln_tree.tag_configure('medium', foreground='orange')
        self.vuln_tree.tag_configure('low', foreground='green')
    
    def _show_vuln_details(self, event):
        """Show detailed vulnerability information."""
        selection = self.vuln_tree.selection()
        if not selection:
            return
        
        item = self.vuln_tree.item(selection[0])
        vuln_id = int(item['text']) - 1
        
        if hasattr(self, 'scan_results') and vuln_id < len(self.scan_results['vulnerabilities']):
            vuln = self.scan_results['vulnerabilities'][vuln_id]
            
            # Create detail window
            detail_window = tk.Toplevel(self.root)
            detail_window.title(f"Vulnerability Details - {vuln.get('type', 'Unknown')}")
            detail_window.geometry("800x600")
            
            # Create text widget with details
            detail_text = scrolledtext.ScrolledText(detail_window, wrap='word')
            detail_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Format details
            details = f"""Vulnerability Details
=====================

Type: {vuln.get('type', 'Unknown')}
Severity: {vuln.get('severity', 'Unknown')}
Confirmed: {'Yes' if vuln.get('confirmed') else 'No'}

URL: {vuln.get('url', 'Unknown')}
Method: {vuln.get('method', 'Unknown')}
Injection Point: {vuln.get('injection_point', 'Unknown')}
Context: {vuln.get('context', 'Unknown')}

Payload:
{vuln.get('payload', 'Unknown')}

Evidence:
{vuln.get('evidence', 'No evidence available')}
"""
            
            detail_text.insert('1.0', details)
            detail_text.config(state='disabled')
    
    def _generate_report(self):
        """Generate report from current scan results."""
        if not hasattr(self, 'scan_results'):
            messagebox.showwarning("Warning", "No scan results available. Please run a scan first.")
            return
        
        # Ask for output directory
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return
        
        output_path = Path(output_dir)
        
        # Generate report based on selected format
        format_type = self.output_format.get()
        
        if format_type == 'html':
            reporter = HTMLReporter()
        elif format_type == 'json':
            reporter = JSONReporter()
        else:
            reporter = CSVReporter()
        
        if reporter.generate(self.scan_results, output_path):
            messagebox.showinfo("Success", f"{format_type.upper()} report generated successfully!")
            
            # Open report location
            import os
            os.startfile(output_path)
        else:
            messagebox.showerror("Error", "Failed to generate report")
    
    def _stop_scan(self):
        """Stop the current scan."""
        # Note: Proper scan cancellation would require more sophisticated threading
        messagebox.showinfo("Info", "Scan stop requested. Current operations will complete.")
        self.stop_button.config(state='disabled')
    
    def _clear_logs(self):
        """Clear the log display."""
        self.log_text.delete('1.0', 'end')
    
    def _save_logs(self):
        """Save logs to file."""
        filename = filedialog.asksaveasfilename(
            title="Save Logs",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text.get('1.0', 'end'))
            messagebox.showinfo("Success", "Logs saved successfully!")
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """GUI entry point."""
    app = XSSScannerGUI()
    app.run()


if __name__ == "__main__":
    main()