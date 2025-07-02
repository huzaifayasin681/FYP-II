import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

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


class SQLiScannerTab:
    def __init__(self, parent):
        self.parent = parent
        self._main_script = os.path.join(PROJECT_ROOT, "main.py")
        self.proc = None
        self._build_widgets()
        self._configure_grid()

    def _configure_grid(self):
        # Make columns expand proportionally
        for col in range(4):
            self.parent.grid_columnconfigure(col, weight=1)

    def _build_widgets(self):
        pad = {"padx": 8, "pady": 6}

        # Preset selector
        ttk.Label(self.parent, text="Preset:").grid(row=0, column=0, sticky="e", **pad)
        self.preset_var = tk.StringVar(value="Custom")
        self.preset_box = ttk.Combobox(
            self.parent,
            textvariable=self.preset_var,
            values=list(PRESETS.keys()),
            state="readonly",
            width=40
        )
        self.preset_box.grid(row=0, column=1, columnspan=3, sticky="we", **pad)
        self.preset_box.bind("<<ComboboxSelected>>", self._apply_preset)

        # Target URL
        ttk.Label(self.parent, text="Target URL:").grid(row=1, column=0, sticky="e", **pad)
        self.url_var = tk.StringVar()
        ttk.Entry(self.parent, textvariable=self.url_var).grid(
            row=1, column=1, columnspan=3, sticky="we", **pad
        )

        # Payload categories
        ttk.Label(self.parent, text="Payloads:").grid(row=2, column=0, sticky="ne", **pad)
        cats = builtin_categories()
        self.lb_cats = tk.Listbox(
            self.parent,
            selectmode="multiple",
            height=min(len(cats), 6),
            exportselection=False
        )
        for cat in cats:
            self.lb_cats.insert(tk.END, cat)
        self.lb_cats.selection_set(0, tk.END)
        self.lb_cats.grid(row=2, column=1, columnspan=3, sticky="we", **pad)

        # UNION marker
        ttk.Label(self.parent, text="UNION Marker:").grid(row=3, column=0, sticky="e", **pad)
        self.marker_var = tk.StringVar(value="SQLISCANNERUNIONTEST")
        ttk.Entry(self.parent, textvariable=self.marker_var).grid(
            row=3, column=1, columnspan=3, sticky="we", **pad
        )

        # Crawl options
        self.crawl_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self.parent, text="Enable crawl", variable=self.crawl_var
        ).grid(row=4, column=0, sticky="w", **pad)
        ttk.Label(self.parent, text="Depth:").grid(row=4, column=1, sticky="e", **pad)
        self.depth_var = tk.StringVar(value="2")
        ttk.Entry(self.parent, width=6, textvariable=self.depth_var).grid(
            row=4, column=2, sticky="w", **pad
        )
        ttk.Label(self.parent, text="Max pages:").grid(row=4, column=3, sticky="e", **pad)
        self.pages_var = tk.StringVar(value="50")
        ttk.Entry(self.parent, width=6, textvariable=self.pages_var).grid(
            row=4, column=4, sticky="w", padx=5, pady=6
        )

        # Report file
        ttk.Label(self.parent, text="Report file:").grid(row=5, column=0, sticky="e", **pad)
        self.output_var = tk.StringVar()
        ttk.Entry(
            self.parent,
            textvariable=self.output_var
        ).grid(row=5, column=1, columnspan=2, sticky="we", **pad)
        ttk.Button(
            self.parent, text="Browse…", command=self._browse_output
        ).grid(row=5, column=3, sticky="w", **pad)

        # Control buttons
        self.run_button = ttk.Button(
            self.parent, text="Run Scan", command=self._on_run
        )
        self.run_button.grid(row=6, column=1, sticky="we", pady=10)
        self.stop_button = ttk.Button(
            self.parent, text="Stop Scan", command=self._on_stop, state="disabled"
        )
        self.stop_button.grid(row=6, column=2, sticky="we", pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(
            self.parent, mode="indeterminate"
        )
        self.progress.grid(row=7, column=0, columnspan=4, sticky="we", **pad)

        # Log/output text area
        self.log_text = tk.Text(
            self.parent, height=15, state="disabled", wrap="word"
        )
        self.log_text.grid(row=8, column=0, columnspan=4, sticky="nsew", **pad)

    def _apply_preset(self, event=None):
        preset = PRESETS.get(self.preset_var.get(), {})
        cats = builtin_categories()
        if "builtins" in preset:
            sel = set(preset["builtins"].split(","))
            for i, cat in enumerate(cats):
                if cat in sel:
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
            filetypes=[
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("HTML", "*.html;*.htm"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.output_var.set(path)

    def _on_run(self):
        url = self.url_var.get().strip()
        output = self.output_var.get().strip()
        if not url:
            messagebox.showwarning(
                "Input required", "Please enter a target URL."
            )
            return
        if not output:
            messagebox.showwarning(
                "Output required", "Please select a report file."
            )
            return

        selected = [self.lb_cats.get(i) for i in self.lb_cats.curselection()]
        builtins_arg = ",".join(selected)
        cmd = [
            sys.executable,
            self._main_script,
            "scan",
            "--url",
            url,
            "--builtins",
            builtins_arg,
            "--marker",
            self.marker_var.get(),
            "--output",
            output,
        ]
        if self.crawl_var.get():
            cmd += [
                "--crawl",
                "--crawl-depth",
                self.depth_var.get(),
                "--crawl-pages",
                self.pages_var.get(),
            ]

        self.run_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress.start()
        self._append_log(f"> {' '.join(cmd)}\n")
        threading.Thread(
            target=self._run_subprocess, args=(cmd,), daemon=True
        ).start()

    def _on_stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self._append_log("[Scan stopped by user]\n")
        self.stop_button.config(state="disabled")
        self.run_button.config(state="normal")
        self.progress.stop()

    def _run_subprocess(self, cmd):
        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
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
            messagebox.showinfo(
                "Scan Complete", "Scan finished successfully."
            )
        elif self.proc and self.proc.returncode != 0:
            messagebox.showwarning(
                "Scan Finished",
                f"Process exited with code {self.proc.returncode}.",
            )

    def _append_log(self, message: str):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")
