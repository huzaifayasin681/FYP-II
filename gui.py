import tkinter as tk
from tkinter import ttk

# from sqli_scanner.gui.sqli_scanner_tab import SQLiScannerTab
# from xss_scanner_tab import XSSScannerTab

from sqli_scanner.gui import SQLiScannerTab
# from xss_scanner.gui import ImprovedXSScannerGUI
from xss_scanner.gui_fixed import ImprovedXSScannerGUI


class UnifiedScannerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Unified Web Security Scanner Suite")
        self.root.geometry("1000x800")

        # Notebook with tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Create frames for each tab
        sqli_frame = ttk.Frame(notebook)
        xss_frame = ttk.Frame(notebook)

        notebook.add(sqli_frame, text="SQLi Scanner")
        notebook.add(xss_frame, text="XSS Scanner")

        # Initialize tabs
        self.sqli_tab = SQLiScannerTab(sqli_frame)
        self.xss_tab = ImprovedXSScannerGUI(xss_frame)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = UnifiedScannerApp()
    app.run()
