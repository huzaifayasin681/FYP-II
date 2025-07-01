"""
Enhanced Tkinter GUI for the SQLi Scanner

Save this as gui.py alongside main.py.
Run with:
    python gui.py
"""
import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Allow relative import when running gui.py directly
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.utils import builtin_categories

PRESETS = {
    "Custom": {},
    "Basic (classic)": {"builtins": "classic", "crawl": False},
    "All Payloads": {"builtins": ",".join(builtin_categories()), "crawl": False},
    "Deep Crawl": {
        "builtins": ",".join(builtin_categories()),
        "crawl": True,
        "crawl_depth": "3",
        "crawl_pages": "200",
    },
}


class SQLiScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SQLi Scanner GUI")
        self.resizable(False, False)
        self._project_root = PROJECT_ROOT
        self._main_script = os.path.join(self._project_root, "main.py")
        self.proc = None
        self._build_widgets()

    def _build_widgets(self):
        pad = {"padx": 5, "pady": 5}

        # Preset selector
        ttk.Label(self, text="Preset:").grid(row=0, column=0, sticky="w", **pad)
        self.preset_var = tk.StringVar(value="Custom")
        self.preset_box = ttk.Combobox(self, textvariable=self.preset_var, values=list(PRESETS.keys()), state="readonly")
        self.preset_box.grid(row=0, column=1, columnspan=3, sticky="we", **pad)
        self.preset_box.bind("<<ComboboxSelected>>", self._apply_preset)

        # URL entry
        ttk.Label(self, text="Target URL:").grid(row=1, column=0, sticky="w", **pad)
        self.url_var = tk.StringVar()
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
        self.output_var = tk.StringVar()
        ttk.Entry(self, width=50, textvariable=self.output_var).grid(row=5, column=1, columnspan=2, **pad)
        ttk.Button(self, text="Browse…", command=self._browse_output).grid(row=5, column=3, **pad)

        # Run & Stop buttons
        self.run_button = ttk.Button(self, text="Run Scan", command=self._on_run)
        self.run_button.grid(row=6, column=0, columnspan=2, **pad)
        self.stop_button = ttk.Button(self, text="Stop Scan", command=self._on_stop, state="disabled")
        self.stop_button.grid(row=6, column=2, columnspan=2, **pad)

        # Progress bar
        self.progress = ttk.Progressbar(self, mode="indeterminate", length=400)
        self.progress.grid(row=7, column=0, columnspan=4, **pad)

        # Log/output text area
        self.log_text = tk.Text(self, width=80, height=20, state="disabled")
        self.log_text.grid(row=8, column=0, columnspan=4, padx=5, pady=(0, 5))

    def _apply_preset(self, event=None):
        preset = PRESETS.get(self.preset_var.get(), {})
        # Clear selections if not specified
        if "builtins" in preset:
            for i, cat in enumerate(builtin_categories()):
                if cat in preset["builtins"].split(","):
                    self.lb_cats.selection_set(i)
                else:
                    self.lb_cats.selection_clear(i)
        else:
            self.lb_cats.selection_set(0, tk.END)
        if "crawl" in preset:
            self.crawl_var.set(preset["crawl"])
        if "crawl_depth" in preset:
            self.depth_var.set(preset["crawl_depth"])
        if "crawl_pages" in preset:
            self.pages_var.set(preset["crawl_pages"])

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("HTML", "*.html;*.htm"), ("All files", "*.*")],
        )
        if path:
            self.output_var.set(path)

    def _on_run(self):
        url = self.url_var.get().strip()
        output = self.output_var.get().strip()
        if not url:
            messagebox.showwarning("Input required", "Please enter a target URL.")
            return
        if not output:
            messagebox.showwarning("Output required", "Please select a report file.")
            return

        selected = [self.lb_cats.get(i) for i in self.lb_cats.curselection()]
        builtins_arg = ",".join(selected) if selected else ""
        cmd = [sys.executable, self._main_script, "scan", "--url", url, "--builtins", builtins_arg,
               "--marker", self.marker_var.get(), "--output", output]
        if self.crawl_var.get():
            cmd += ["--crawl", "--crawl-depth", self.depth_var.get(), "--crawl-pages", self.pages_var.get()]

        self.run_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress.start()
        self._append_log(f"> {' '.join(cmd)}\n")
        threading.Thread(target=self._run_subprocess, args=(cmd,), daemon=True).start()

    def _on_stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self._append_log("[Scan stopped by user]\n")
        self.stop_button.config(state="disabled")
        self.run_button.config(state="normal")
        self.progress.stop()

    def _run_subprocess(self, cmd):
        try:
            self.proc = subprocess.Popen(cmd, cwd=self._project_root,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, bufsize=1)
        except Exception as e:
            self._append_log(f"[Error launching scan] {e}\n")
            self._finish_scan()
            return

        for line in self.proc.stdout:
            self._append_log(line)
        self.proc.wait()
        self._append_log(f"\n[Process exited with code {self.proc.returncode}]\n")
        self._finish_scan()

    def _finish_scan(self):
        self.progress.stop()
        self.stop_button.config(state="disabled")
        self.run_button.config(state="normal")
        if self.proc and self.proc.returncode == 0:
            messagebox.showinfo("Scan Complete", "Scan finished successfully.")
        elif self.proc and self.proc.returncode != 0:
            messagebox.showwarning("Scan Finished", f"Process exited with code {self.proc.returncode}.")

    def _append_log(self, message: str):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")


if __name__ == "__main__":
    app = SQLiScannerGUI()
    app.mainloop()
