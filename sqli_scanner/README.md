````markdown
# SQLi Scanner

Automated SQL‐injection vulnerability scanner for web applications.  
Fuzzes URL query parameters and HTML forms, detects error‐based, time‐based, boolean‐based and UNION‐based SQLi, and writes JSON/CSV/HTML reports.

---

## Installation

1. Clone and install dependencies:
   ```bash
   git clone https://github.com/yourname/sqli_scanner.git && cd sqli_scanner && pip install -r requirements.txt
````

2. (Optional) Install in editable mode:

   ```bash
   pip install -e .
   ```

---

## Quick CLI Usage

* **Show help**

  ```bash
  python main.py --help
  ```
* **List built-in payload categories**

  ```bash
  python main.py list-builtins
  ```
* **Scan a single URL**

  ```bash
  python main.py scan --url "http://example.com/page.php?id=1"
  ```
* **Save a JSON report**

  ```bash
  python main.py scan --url "http://example.com/page.php?id=1" --output reports/scan.json
  ```
* **Save a CSV report**

  ```bash
  python main.py scan --url "http://example.com/page.php?id=1" --output reports/scan.csv
  ```
* **Save an HTML report**

  ```bash
  python main.py scan --url "http://example.com/page.php?id=1" --output reports/scan.html
  ```
* **Advanced scan** (custom payloads, marker, crawler)

  ```bash
  python main.py scan --url "http://example.com/page.php?id=1" --builtins classic,time,boolean,union,waf-bypass --marker MYMARKER --crawl --crawl-depth 3 --crawl-pages 100 --output reports/full.html
  ```
* **Use a config file**

  ```bash
  python main.py scan --config config/default.yaml
  ```

---

## GUI Usage

1. Ensure dependencies are installed:

   ```bash
   pip install -r requirements.txt
   ```
2. Run the GUI:

   ```bash
   python gui.py
   ```
3. Fill in the fields (URL, payload groups, marker, crawl options, output file) and click **Run Scan**. View progress and logs in the window.

---

## Configuration (`config/default.yaml`)

```yaml
targets:
  - "http://example.com/page.php?id=1"
builtin_payloads:
  - classic
  - union
  - time
  - boolean
  - waf-bypass
union_marker: "SQLISCANNERUNIONTEST"
crawl: true
crawl_depth: 2
crawl_pages: 50
rate_limit: 5
retries: 3
timeout: 10
threads: 10
async_mode: false
detection:
  error_based: true
  time_based: true
  boolean_based: true
  union_based: true
report_file: ""
logging_level: "INFO"
```

---

## Folder Structure

```
sqli_scanner/
├── scanner/
│   ├── core.py         ← main orchestration
│   ├── utils.py        ← config, rate‐limit, payload/target loading
│   ├── requester.py    ← HTTP engine (sync & async)
│   ├── detector.py     ← detection logic
│   ├── parser.py       ← GET params & form parsing
│   └── crawler.py      ← optional site crawler
├── reports/
│   ├── json_report.py  ← JSON exporter
│   ├── csv_report.py   ← CSV exporter
│   └── html_report.py  ← HTML exporter
├── config/
│   └── default.yaml    ← example config
├── payloads/
│   └── default.txt     ← sample payloads
├── cli.py              ← Typer CLI
├── main.py             ← CLI entry‐point
├── gui.py              ← Tkinter GUI
├── requirements.txt    ← dependencies
└── README.md           ← this file
```

---

## How It Works

1. **Load config & CLI flags** with precedence: CLI > config file > defaults.
2. **Load payloads** — built‐in groups, custom files, inline strings.
3. **Load targets** — single URL or list from file.
4. **(Optional) Crawl** seed URLs to discover more pages & forms.
5. **Baseline requests** for each page and form (default values).
6. **Fuzzing**

   * **GET**: replace each query‐param one at a time with every payload.
   * **POST/GET forms**: submit each field one at a time with every payload.
7. **Detection** compares baseline and variant responses:

   * **Error‐based**: known SQL error patterns.
   * **Time‐based**: payloads that induce delays.
   * **Boolean‐based**: content differences in true/false payloads.
   * **UNION‐based**: custom marker echoed back.
8. **Reporting** writes findings to JSON, CSV, or HTML based on the `--output` extension.

---

Happy fuzzing!
Feel free to open issues or contribute new payloads, detection rules, or exporters.
