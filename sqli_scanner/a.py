import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import webbrowser
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import random
import json
import csv
import html
from urllib.parse import urlparse, parse_qs, urlunparse, urljoin  # Fixed import

# Set up project paths
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Try importing SQLi scanner components
try:
    from scanner.utils import builtin_categories
    SQLI_ENABLED = True
except ImportError as e:
    print(f"SQLi import error: {e}")
    SQLI_ENABLED = False

class UnifiedScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Unified Web Vulnerability Scanner")
        self.geometry("900x700")
        self.resizable(True, True)
        self.proc = None
        self.scanning = False
        self.last_report = None
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        if SQLI_ENABLED:
            self.sqliscanner_tab = SQLiScannerTab(self.notebook, self)
            self.notebook.add(self.sqliscanner_tab, text='SQL Injection Scanner')
        
        self.xsscanner_tab = XSSScannerTab(self.notebook, self)
        self.notebook.add(self.xsscanner_tab, text='XSS Scanner')
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to scan")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # View report button
        self.view_report_btn = ttk.Button(self, text="View Last Report", command=self._view_report)
        self.view_report_btn.pack(side=tk.BOTTOM, pady=5)

    def _log(self, message, tag='INFO'):
        active_tab = self.notebook.tab(self.notebook.select(), "text")
        
        if active_tab == 'SQL Injection Scanner' and SQLI_ENABLED:
            self.sqliscanner_tab.log(message, tag)
        else:
            self.xsscanner_tab.log(message, tag)
        
        self.update()
        
    def _update_status(self, message):
        self.status_var.set(message)
        self.update()
        
    def _view_report(self):
        if self.last_report and self.last_report.exists():
            webbrowser.open(str(self.last_report))
        else:
            messagebox.showinfo("Info", "No report found. Run a scan first.")

class SQLiScannerTab(ttk.Frame):
    SQLI_PRESETS = {
        "Custom": {},
        "Basic (classic)": {"builtins": "classic", "crawl": False},
        "All Payloads": {"builtins": "all", "crawl": False},
        "Deep Crawl": {"builtins": "all", "crawl": True, "crawl_depth": "3", "crawl_pages": "200"},
    }

    def __init__(self, parent, main_app):
        super().__init__(parent)
        self.main_app = main_app
        self.preset_var = tk.StringVar(value="Custom")
        self._build_widgets()
        
    def _build_widgets(self):
        pad = {"padx": 5, "pady": 5}

        # Preset selector
        ttk.Label(self, text="Preset:").grid(row=0, column=0, sticky="w", **pad)
        self.preset_box = ttk.Combobox(
            self,
            textvariable=self.preset_var,
            values=list(self.SQLI_PRESETS.keys()),
            state="readonly"
        )
        self.preset_box.grid(row=0, column=1, columnspan=3, sticky="we", **pad)
        self.preset_box.bind("<<ComboboxSelected>>", self._apply_preset)

        # URL entry
        ttk.Label(self, text="Target URL:").grid(row=1, column=0, sticky="w", **pad)
        self.url_var = tk.StringVar(value="http://testphp.vulnweb.com")
        ttk.Entry(self, width=60, textvariable=self.url_var).grid(row=1, column=1, columnspan=3, **pad)

        # Built-in payload categories
        ttk.Label(self, text="Payloads:").grid(row=2, column=0, sticky="nw", **pad)
        cats = builtin_categories()
        self.lb_cats = tk.Listbox(self, selectmode="multiple", height=min(len(cats), 6), exportselection=False)
        for cat in cats:
            self.lb_cats.insert(tk.END, cat)
        self.lb_cats.selection_set(0, tk.END)
        self.lb_cats.grid(row=2, column=1, sticky="w", **pad)

        # UNION marker
        ttk.Label(self, text="UNION Marker:").grid(row=3, column=0, sticky="w", **pad)
        self.marker_var = tk.StringVar(value="SQLISCANNERUNIONTEST")
        ttk.Entry(self, width=30, textvariable=self.marker_var).grid(row=3, column=1, **pad)

        # Crawl options
        self.crawl_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Enable crawl", variable=self.crawl_var).grid(row=3, column=2, **pad)
        ttk.Label(self, text="Depth:").grid(row=4, column=0, sticky="e", **pad)
        self.depth_var = tk.StringVar(value="2")
        ttk.Entry(self, width=5, textvariable=self.depth_var).grid(row=4, column=1, sticky="w", **pad)
        ttk.Label(self, text="Max pages:").grid(row=4, column=2, sticky="e", **pad)
        self.pages_var = tk.StringVar(value="50")
        ttk.Entry(self, width=5, textvariable=self.pages_var).grid(row=4, column=3, sticky="w", **pad)

        # Output file
        ttk.Label(self, text="Report file:").grid(row=5, column=0, sticky="w", **pad)
        self.output_var = tk.StringVar(value=str(PROJECT_ROOT / "reports" / "sqli_report.html"))
        ttk.Entry(self, width=50, textvariable=self.output_var).grid(row=5, column=1, columnspan=2, **pad)
        ttk.Button(self, text="Browse...", command=self._browse_output).grid(row=5, column=3, **pad)

        # Run & Stop buttons
        self.run_button = ttk.Button(self, text="Run Scan", command=self._on_run)
        self.run_button.grid(row=6, column=0, columnspan=2, **pad)
        self.stop_button = ttk.Button(self, text="Stop Scan", command=self._on_stop, state="disabled")
        self.stop_button.grid(row=6, column=2, columnspan=2, **pad)

        # Progress bar
        self.progress = ttk.Progressbar(self, mode="indeterminate", length=400)
        self.progress.grid(row=7, column=0, columnspan=4, **pad)

        # Log/output text area
        self.log_text = tk.Text(self, width=80, height=15, state="disabled")
        self.log_text.grid(row=8, column=0, columnspan=4, padx=5, pady=(0, 5))
        
        # Configure tags for colored output
        self.log_text.tag_config('INFO', foreground='blue')
        self.log_text.tag_config('SUCCESS', foreground='green')
        self.log_text.tag_config('WARNING', foreground='orange')
        self.log_text.tag_config('ERROR', foreground='red')
        self.log_text.tag_config('VULN', foreground='red', font=('Arial', 10, 'bold'))
        
    def log(self, message, tag='INFO'):
        self.log_text.config(state="normal")
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert('end', f"[{timestamp}] {message}\n", tag)
        self.log_text.see('end')
        self.log_text.config(state="disabled")
        
    def _apply_preset(self, event=None):
        preset = self.SQLI_PRESETS.get(self.preset_var.get(), {})
        if "builtins" in preset:
            self.lb_cats.selection_clear(0, tk.END)
            if preset["builtins"] == "all":
                self.lb_cats.selection_set(0, tk.END)
            elif preset["builtins"] == "classic":
                for i, cat in enumerate(builtin_categories()):
                    if "classic" in cat.lower():
                        self.lb_cats.selection_set(i)
        if "crawl" in preset:
            self.crawl_var.set(preset["crawl"])
        if "crawl_depth" in preset:
            self.depth_var.set(preset["crawl_depth"])
        if "crawl_pages" in preset:
            self.pages_var.set(preset["crawl_pages"])

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("JSON", "*.json"), ("CSV", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.output_var.set(path)

    def _on_run(self):
        url = self.url_var.get().strip()
        output = self.output_var.get().strip()
        if not url:
            messagebox.showwarning("Input required", "Please enter a target URL.")
            return
        
        # Ensure output directory exists
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        selected = [self.lb_cats.get(i) for i in self.lb_cats.curselection()]
        builtins_arg = ",".join(selected) if selected else ""
        cmd = [sys.executable, str(PROJECT_ROOT/"main.py"), "scan", "--url", url, 
               "--builtins", builtins_arg, "--marker", self.marker_var.get(), "--output", output]
        
        if self.crawl_var.get():
            cmd += ["--crawl", "--crawl-depth", self.depth_var.get(), "--crawl-pages", self.pages_var.get()]

        self.run_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress.start()
        self.log(f"> {' '.join(cmd)}\n")
        self.main_app._update_status("SQLi Scan running...")
        threading.Thread(target=self._run_subprocess, args=(cmd, output_path), daemon=True).start()

    def _on_stop(self):
        if self.main_app.proc and self.main_app.proc.poll() is None:
            self.main_app.proc.terminate()
            self.log("[Scan stopped by user]\n")
        self.stop_button.config(state="disabled")
        self.run_button.config(state="normal")
        self.progress.stop()
        self.main_app._update_status("Scan stopped")

    def _run_subprocess(self, cmd, output_path):
        try:
            self.main_app.proc = subprocess.Popen(
                cmd,
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in self.main_app.proc.stdout:
                self.log(line)
            self.main_app.proc.wait()
            self.log(f"\n[Process exited with code {self.main_app.proc.returncode}]\n")
        except Exception as e:
            self.log(f"[Error launching scan] {e}\n", "ERROR")
        finally:
            self._finish_scan(output_path)

    def _finish_scan(self, output_path):
        self.progress.stop()
        self.stop_button.config(state="disabled")
        self.run_button.config(state="normal")
        
        if self.main_app.proc and self.main_app.proc.returncode == 0:
            self.log("✅ Scan completed successfully!", 'SUCCESS')
            self.main_app.last_report = output_path
            self.main_app._update_status("SQLi Scan complete")
            messagebox.showinfo("Scan Complete", "Scan finished successfully.")
        elif self.main_app.proc and self.main_app.proc.returncode != 0:
            self.log("❌ Scan completed with errors", 'ERROR')
            self.main_app._update_status("Scan completed with errors")
            messagebox.showwarning("Scan Finished", f"Process exited with code {self.main_app.proc.returncode}.")

class XSSScannerTab(ttk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)
        self.main_app = main_app
        self.scan_thread = None
        self.stop_requested = False
        self._create_widgets()
        
    def _create_widgets(self):
        # Configuration frame
        config_frame = ttk.LabelFrame(self, text="Scan Configuration", padding=10)
        config_frame.pack(fill='x', padx=10, pady=5)
        
        # Target URL
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_url = tk.StringVar(value="http://testphp.vulnweb.com")
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
        target_combo.bind('<<ComboboxSelected>>', 
                         lambda e: self.target_url.set(target_combo.get()) 
                         if target_combo.get() != "Custom URL" else None)
        
        # Scan depth
        ttk.Label(config_frame, text="Crawl Depth:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.scan_depth = tk.IntVar(value=2)
        ttk.Spinbox(config_frame, from_=1, to=5, textvariable=self.scan_depth, width=10).grid(
            row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Max URLs
        ttk.Label(config_frame, text="Max URLs to test:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.max_urls = tk.IntVar(value=10)
        ttk.Spinbox(config_frame, from_=5, to=100, textvariable=self.max_urls, width=10, increment=5).grid(
            row=2, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Report file
        ttk.Label(config_frame, text="Report file:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.output_var = tk.StringVar(value=str(PROJECT_ROOT / "reports" / "xss_report.html"))
        ttk.Entry(config_frame, textvariable=self.output_var, width=50).grid(row=3, column=1, columnspan=2, pady=5, padx=5)
        ttk.Button(config_frame, text="Browse...", command=self._browse_output).grid(row=3, column=3, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self._stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=10, pady=5)
        
        # Output area
        output_frame = ttk.LabelFrame(self, text="Scan Output", padding=5)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        self.output_text.pack(fill='both', expand=True)
        
        # Configure tags for colored output
        self.output_text.tag_config('INFO', foreground='blue')
        self.output_text.tag_config('SUCCESS', foreground='green')
        self.output_text.tag_config('WARNING', foreground='orange')
        self.output_text.tag_config('ERROR', foreground='red')
        self.output_text.tag_config('VULN', foreground='red', font=('Arial', 10, 'bold'))
        
    def log(self, message, tag='INFO'):
        self.output_text.config(state='normal')
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.output_text.insert('end', f"[{timestamp}] {message}\n", tag)
        self.output_text.see('end')
        self.output_text.config(state='disabled')
        self.main_app.update()
        
    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("JSON", "*.json"), ("CSV", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.output_var.set(path)
        
    def _start_scan(self):
        if not self.target_url.get():
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        if self.main_app.scanning:
            messagebox.showwarning("Warning", "Scan already in progress")
            return
            
        self.main_app.scanning = True
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.stop_requested = False
        self.progress_var.set(0)
        
        # Clear previous output
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', 'end')
        self.output_text.config(state='disabled')
        self.log(f"Starting XSS scan of {self.target_url.get()}", 'INFO')
        
        # Run scan in thread
        self.scan_thread = threading.Thread(target=self._run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def _run_scan(self):
        try:
            # Create output directory
            output_path = Path(self.output_var.get())
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Start scanning
            self.main_app._update_status("XSS Scan running...")
            self.log("🕷️ Crawling website to find URLs and forms...", 'INFO')
            
            # Crawl website
            urls, forms = self.crawl_website(self.target_url.get(), self.scan_depth.get(), self.max_urls.get())
            
            if self.stop_requested:
                self.log("Scan stopped by user", "WARNING")
                return
                
            self.log(f"✅ Found {len(urls)} URLs and {len(forms)} forms", 'SUCCESS')
            self.progress_var.set(30)
            
            # Test for XSS vulnerabilities
            self.log("💉 Testing for XSS vulnerabilities...", 'INFO')
            vulnerabilities = self.test_xss(urls, forms)
            
            if self.stop_requested:
                self.log("Scan stopped by user", "WARNING")
                return
                
            # Generate report
            self.log("📊 Generating report...", 'INFO')
            report_path = self.generate_report(vulnerabilities, output_path)
            
            # Update UI
            self.progress_var.set(100)
            self.log(f"✅ XSS Scan completed! Found {len(vulnerabilities)} vulnerabilities", 'SUCCESS')
            self.log(f"📄 Report saved to: {report_path}", 'SUCCESS')
            self.main_app.last_report = report_path
            self.main_app._update_status("XSS Scan complete")
            
        except Exception as e:
            self.log(f"Error during XSS scan: {str(e)}", 'ERROR')
            self.main_app._update_status("XSS Scan failed")
            
        finally:
            self.main_app.scanning = False
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')
            
    def crawl_website(self, base_url, max_depth, max_urls):
        """Crawl website to find URLs and forms."""
        visited = set()
        urls = set()
        forms = []
        
        to_visit = [(base_url, 0)]
        
        while to_visit and len(urls) < max_urls and not self.stop_requested:
            url, depth = to_visit.pop(0)
            
            if depth > max_depth:
                continue
                
            if url in visited:
                continue
                
            visited.add(url)
            
            try:
                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Add URL to list
                urls.add(url)
                self.log(f"Found URL: {url}", 'INFO')
                
                # Find all forms on the page
                for form in soup.find_all('form'):
                    form_details = {
                        'action': form.get('action'),
                        'method': form.get('method', 'get').lower(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all('input'):
                        input_details = {
                            'type': input_tag.get('type', 'text'),
                            'name': input_tag.get('name'),
                            'value': input_tag.get('value', '')
                        }
                        form_details['inputs'].append(input_details)
                    
                    forms.append(form_details)
                    self.log(f"Found form: {form_details['action']}", 'INFO')
                
                # Find links for next level of crawling
                if depth < max_depth:
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('http'):
                            absolute_url = href
                        else:
                            absolute_url = urljoin(url, href)  # Fixed URL joining
                        
                        if absolute_url not in visited:
                            to_visit.append((absolute_url, depth + 1))
                            
                # Update progress
                progress = 30 + (50 * len(urls) / max_urls)
                self.progress_var.set(min(progress, 80))
                
            except Exception as e:
                self.log(f"Error crawling {url}: {str(e)}", 'ERROR')
        
        return urls, forms
    
    def test_xss(self, urls, forms):
        """Test URLs and forms for XSS vulnerabilities."""
        vulnerabilities = []
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        total_tests = len(urls) + len(forms)
        current_test = 0
        
        # Test URLs with query parameters
        for url in urls:
            if self.stop_requested:
                return vulnerabilities
                
            current_test += 1
            self.progress_var.set(30 + (50 * current_test) / total_tests)
            
            parsed_url = urlparse(url)  # Fixed URL parsing
            query = parse_qs(parsed_url.query)  # Fixed query parsing
            
            if not query:
                continue
                
            self.log(f"Testing URL: {url}", 'INFO')
            
            for param in query:
                original_value = query[param][0]
                
                for payload in payloads:
                    modified_query = query.copy()
                    modified_query[param] = [payload]
                    
                    # Reconstruct URL
                    new_query = "&".join(f"{k}={v[0]}" for k, v in modified_query.items())
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    
                    try:
                        response = requests.get(test_url, timeout=5)
                        if payload in response.text:
                            vuln = {
                                'type': 'Reflected XSS',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'severity': 'High'
                            }
                            vulnerabilities.append(vuln)
                            self.log(f"⚠️ Found XSS vulnerability in parameter: {param}", 'VULN')
                            break
                    except Exception as e:
                        self.log(f"Error testing {test_url}: {str(e)}", 'ERROR')
        
        # Test forms
        for form in forms:
            if self.stop_requested:
                return vulnerabilities
                
            current_test += 1
            self.progress_var.set(30 + (50 * current_test) / total_tests)
            
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            # Build form data
            form_data = {}
            for input_field in inputs:
                name = input_field['name']
                if name:
                    form_data[name] = input_field['value']
            
            self.log(f"Testing form: {action}", 'INFO')
            
            for input_field in inputs:
                if not input_field['name']:
                    continue
                    
                for payload in payloads:
                    # Create modified form data
                    modified_data = form_data.copy()
                    modified_data[input_field['name']] = payload
                    
                    try:
                        if method == 'post':
                            response = requests.post(action, data=modified_data, timeout=5)
                        else:
                            response = requests.get(action, params=modified_data, timeout=5)
                        
                        if payload in response.text:
                            vuln = {
                                'type': 'Stored XSS' if 'Stored' in response.text else 'Reflected XSS',
                                'url': action,
                                'parameter': input_field['name'],
                                'payload': payload,
                                'severity': 'High'
                            }
                            vulnerabilities.append(vuln)
                            self.log(f"⚠️ Found XSS vulnerability in form field: {input_field['name']}", 'VULN')
                            break
                    except Exception as e:
                        self.log(f"Error testing form {action}: {str(e)}", 'ERROR')
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities, output_path):
        """Generate HTML report of vulnerabilities."""
        report = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .vulnerable { color: red; font-weight: bold; }
            </style>
        </head>
        <body>
            <h1>XSS Vulnerability Report</h1>
            <p><strong>Scan Date:</strong> {scan_date}</p>
            <p><strong>Total Vulnerabilities Found:</strong> {vuln_count}</p>
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Severity</th>
                </tr>
                {vuln_rows}
            </table>
        </body>
        </html>
        """
        
        # Create vulnerability rows
        vuln_rows = ""
        for vuln in vulnerabilities:
            vuln_rows += f"""
            <tr>
                <td>{vuln['type']}</td>
                <td>{html.escape(vuln['url'])}</td>
                <td>{html.escape(vuln['parameter'])}</td>
                <td class="vulnerable">{html.escape(vuln['payload'])}</td>
                <td>{vuln['severity']}</td>
            </tr>
            """
        
        # Format report
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = report.format(
            scan_date=scan_date,
            vuln_count=len(vulnerabilities),
            vuln_rows=vuln_rows
        )
        
        # Save report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        return output_path
            
    def _stop_scan(self):
        self.stop_requested = True
        self.log("Scan stopped by user", 'WARNING')
        self.main_app._update_status("Scan stopped")

if __name__ == "__main__":
    app = UnifiedScannerGUI()
    app.mainloop()