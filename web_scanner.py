"""
chaitanya elevate labs 
mini web_scanner
Simple web app security scanner (XSS, SQLi, CSRF checks).
Usage:
    pip install -r requirements.txt
    python web_scanner.py
Open http://127.0.0.1:5000 and start scans.

NOTE: For demo / small targets only. Don't run against large sites or without permission.
"""

from flask import Flask, request, render_template_string, redirect, url_for
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
import time
import uuid

app = Flask(__name__)
USER_AGENT = "MiniScanner/1.0 (+https://example.org)"
HEADERS = {"User-Agent": USER_AGENT}
REQUEST_TIMEOUT = 10

# ==== Simple payload sets ====
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1\" -- ",
    "'; WAITFOR DELAY '0:0:2' --",
    "\"; SELECT pg_sleep(2); --",
]

# SQL error signatures (common)
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "pg_query()",
    "mysql_fetch",
    "syntax error at or near",
    "picoftheday",  # just an example; keep generic list
]

# Severity mapping
SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Results store (in-memory + persisted to file)
SCAN_RESULTS = {}  # scan_id -> list of issues


# ==== Utilities ====
def log_issue(scan_id, issue):
    """Store issue; persist to file scan_{scan_id}.json"""
    if scan_id not in SCAN_RESULTS:
        SCAN_RESULTS[scan_id] = []
    SCAN_RESULTS[scan_id].append(issue)
    # persist
    with open(f"scan_{scan_id}.json", "w") as f:
        json.dump({"scan_id": scan_id, "issues": SCAN_RESULTS[scan_id]}, f, indent=2)


def normalize_url(base, link):
    return urljoin(base, link)


def same_domain(a, b):
    return urlparse(a).netloc == urlparse(b).netloc


# ==== Crawler / form discovery ====
def crawl(start_url, max_pages=50):
    """Crawl pages from start_url (basic BFS). Returns unique URLs found."""
    visited = set()
    to_visit = [start_url]
    result = set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except Exception:
            visited.add(url)
            continue
        visited.add(url)
        result.add(url)
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = normalize_url(url, a["href"])
            # filter fragments and mailto/tel
            if link.startswith("mailto:") or link.startswith("tel:"):
                continue
            # normalize fragment removal
            link = link.split("#")[0]
            if same_domain(start_url, link) and link not in visited:
                to_visit.append(link)
    return list(result)


def extract_forms(html, base_url):
    """Return list of forms with action, method, inputs (name,type,value)"""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        f = {}
        f["action"] = normalize_url(base_url, form.get("action", ""))
        f["method"] = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                # some inputs lack name -> not submitted
                continue
            t = inp.get("type", "text")
            value = inp.get("value", "") if inp.name == "input" else (inp.text or "")
            inputs.append({"name": name, "type": t, "value": value})
        f["inputs"] = inputs
        forms.append(f)
    return forms


# ==== Test helpers ====
def submit_form(session, form, payloads_map=None):
    """
    Build and submit data for the form. payloads_map: dict input_name -> payload_string
    Returns requests.Response or None
    """
    url = form["action"]
    method = form["method"]
    data = {}
    for inp in form["inputs"]:
        name = inp["name"]
        if payloads_map and name in payloads_map:
            data[name] = payloads_map[name]
        else:
            # keep default benign value
            if inp["type"] in ("text", "search", "textarea"):
                data[name] = inp.get("value", "test")
            elif inp["type"] in ("hidden",):
                data[name] = inp.get("value", "")
            else:
                data[name] = inp.get("value", "")
    try:
        if method == "post":
            return session.post(url, data=data, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        else:
            return session.get(url, params=data, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        return None


def detect_reflected_xss(resp_text, payload):
    """Simple reflected XSS detection by seeing if payload appears verbatim in response (basic)."""
    if not resp_text:
        return False
    return payload in resp_text


def detect_sql_error(resp_text):
    if not resp_text:
        return None
    lowered = resp_text.lower()
    for sig in SQL_ERRORS:
        if sig in lowered:
            return sig
    return None


# ==== Tests ====
def test_xss(session, target_url, scan_id):
    """Find forms and test reflected XSS by injecting payloads into text inputs and looking for reflection."""
    issues = []
    try:
        r = session.get(target_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    except Exception:
        return issues
    forms = extract_forms(r.text, target_url)
    for form in forms:
        for payload in XSS_PAYLOADS:
            payload_map = {inp["name"]: payload for inp in form["inputs"] if inp["type"] in ("text", "search", "textarea")}
            if not payload_map:
                continue
            resp = submit_form(session, form, payload_map)
            evidence = ""
            if resp and detect_reflected_xss(resp.text, payload):
                evidence = f"Payload reflected in response for form action {form['action']}"
                issue = {
                    "id": str(uuid.uuid4()),
                    "type": "Reflected XSS",
                    "target": form["action"],
                    "payload": payload,
                    "evidence": evidence,
                    "severity": "high",
                    "cvss": None,
                    "timestamp": time.time(),
                }
                log_issue(scan_id, issue)
                issues.append(issue)
                # break for this form once we find XSS
                break
    return issues


def test_sqli(session, target_url, scan_id):
    """Test forms and GET params for SQLi using payload injection and checking for SQL errors or response differences."""
    issues = []
    try:
        r = session.get(target_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    except Exception:
        return issues
    base_text = r.text or ""
    forms = extract_forms(r.text, target_url)

    # Test forms
    for form in forms:
        for payload in SQLI_PAYLOADS:
            payload_map = {inp["name"]: payload for inp in form["inputs"] if inp["type"] in ("text", "search", "textarea")}
            if not payload_map:
                continue
            resp = submit_form(session, form, payload_map)
            if not resp:
                continue
            err = detect_sql_error(resp.text)
            if err:
                issue = {
                    "id": str(uuid.uuid4()),
                    "type": "SQL Injection (error-based)",
                    "target": form["action"],
                    "payload": payload,
                    "evidence": f"SQL error signature found: {err}",
                    "severity": "high",
                    "timestamp": time.time(),
                }
                log_issue(scan_id, issue)
                issues.append(issue)
                break
            # boolean-based difference
            if len(resp.text) != len(base_text):
                issue = {
                    "id": str(uuid.uuid4()),
                    "type": "SQL Injection (response-difference)",
                    "target": form["action"],
                    "payload": payload,
                    "evidence": f"Response length differs. baseline {len(base_text)} vs {len(resp.text)}",
                    "severity": "medium",
                    "timestamp": time.time(),
                }
                log_issue(scan_id, issue)
                issues.append(issue)
                break

    # Test GET params on the page URL itself (naive)
    parsed = urlparse(target_url)
    # build simple param tests by appending ?q=payload if no params present
    if "?" not in target_url:
        for payload in SQLI_PAYLOADS:
            test_url = target_url
            if test_url.endswith("/"):
                test_url = test_url[:-1]
            test_url = test_url + "?q=" + requests.utils.requote_uri(payload)
            try:
                r2 = session.get(test_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            except Exception:
                continue
            err = detect_sql_error(r2.text)
            if err:
                issue = {
                    "id": str(uuid.uuid4()),
                    "type": "SQL Injection (error-based) GET",
                    "target": test_url,
                    "payload": payload,
                    "evidence": f"SQL error signature found: {err}",
                    "severity": "high",
                    "timestamp": time.time(),
                }
                log_issue(scan_id, issue)
                issues.append(issue)
                break
            if abs(len(r2.text) - len(base_text)) > 50:
                issue = {
                    "id": str(uuid.uuid4()),
                    "type": "SQL Injection (response-diff) GET",
                    "target": test_url,
                    "payload": payload,
                    "evidence": f"Response length differs by >50 bytes compared to baseline.",
                    "severity": "medium",
                    "timestamp": time.time(),
                }
                log_issue(scan_id, issue)
                issues.append(issue)
                break

    return issues


def test_csrf(session, target_url, scan_id):
    """Naive CSRF detection:
       - For forms that look state-changing (method POST) check for anti-CSRF tokens (hidden inputs named csrf, token, _csrf)
       - For links/buttons that perform GET but appear to change state (contains delete, logout) flag as low/medium risk.
    """
    issues = []
    try:
        r = session.get(target_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    except Exception:
        return issues
    forms = extract_forms(r.text, target_url)
    for form in forms:
        if form["method"].lower() == "post":
            token_found = False
            for inp in form["inputs"]:
                if re.search(r"csrf|token|_csrf|authenticity_token", inp["name"], flags=re.I):
                    token_found = True
                    break
            if not token_found:
                issue = {
                    "id": str(uuid.uuid4()),
                    "type": "CSRF - missing CSRF token",
                    "target": form["action"],
                    "evidence": "POST form without CSRF token-like parameter",
                    "severity": "medium",
                    "timestamp": time.time(),
                }
                log_issue(scan_id, issue)
                issues.append(issue)
    # naive link checks
    soup = BeautifulSoup(r.text, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        if any(k in href for k in ("logout", "delete", "remove", "destroy")) and href.startswith("http"):
            issue = {
                "id": str(uuid.uuid4()),
                "type": "CSRF - unsafe state-changing GET",
                "target": normalize_url(target_url, href),
                "evidence": "State-changing action accessible via GET link",
                "severity": "low",
                "timestamp": time.time(),
            }
            log_issue(scan_id, issue)
            issues.append(issue)
    return issues


# ==== Main scan workflow ====
def run_scan(start_url, max_pages=30):
    """Run a basic scan across crawled pages and return scan_id."""
    scan_id = str(int(time.time()))
    SCAN_RESULTS[scan_id] = []
    session = requests.Session()
    session.headers.update(HEADERS)

    # Crawl
    pages = crawl(start_url, max_pages=max_pages)
    for page in pages:
        # XSS
        test_xss(session, page, scan_id)
        # SQLi
        test_sqli(session, page, scan_id)
        # CSRF
        test_csrf(session, page, scan_id)
    # save final results also in a master file
    with open(f"scan_{scan_id}_summary.json", "w") as f:
        json.dump({"scan_id": scan_id, "issues": SCAN_RESULTS.get(scan_id, [])}, f, indent=2)
    return scan_id


# ==== Minimal Flask UI ====
INDEX_HTML = """
<!doctype html>
<title>Mini Web Scanner</title>
<h1>Mini Web Scanner</h1>
<form method="post" action="/start">
  Target URL: <input name="target" style="width:400px" placeholder="https://example.com"><br>
  Max pages to crawl: <input name="max_pages" value="20" style="width:80px"><br><br>
  <button type="submit">Start Scan</button>
</form>
<hr>
<h3>Previous Scans</h3>
<ul>
{% for sid in scans %}
  <li><a href="{{ url_for('view_scan', scan_id=sid) }}">Scan {{sid}}</a></li>
{% else %}
  <li>No scans yet</li>
{% endfor %}
</ul>
"""

SCAN_HTML = """
<!doctype html>
<title>Scan Results</title>
<h1>Scan {{ scan_id }}</h1>
<p>Found {{ issues|length }} issues</p>
<table border="1" cellpadding="6" cellspacing="0">
  <tr><th>Type</th><th>Target</th><th>Severity</th><th>Evidence</th><th>Payload</th></tr>
  {% for it in issues %}
    <tr>
      <td>{{ it.type }}</td>
      <td><code>{{ it.target }}</code></td>
      <td>{{ it.severity }}</td>
      <td>{{ it.evidence }}</td>
      <td>{{ it.payload if it.payload else "" }}</td>
    </tr>
  {% endfor %}
</table>
<p><a href="{{ url_for('index') }}">Back</a></p>
"""

@app.route("/")
def index():
    scans = sorted([k for k in SCAN_RESULTS.keys()], reverse=True)
    return render_template_string(INDEX_HTML, scans=scans)


@app.route("/start", methods=["POST"])
def start():
    target = request.form.get("target")
    max_pages = int(request.form.get("max_pages") or 20)
    if not target:
        return "Provide target", 400
    # Basic normalization
    if not urlparse(target).scheme:
        target = "http://" + target
    # Run scan synchronously (simple)
    scan_id = run_scan(target, max_pages=max_pages)
    return redirect(url_for("view_scan", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def view_scan(scan_id):
    issues = SCAN_RESULTS.get(scan_id, [])
    return render_template_string(SCAN_HTML, scan_id=scan_id, issues=issues)


if __name__ == "__main__":
    print("Starting Mini Web Scanner on http://127.0.0.1:5000")
    app.run(debug=True)
