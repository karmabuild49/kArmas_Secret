#!/usr/bin/env python3
import os, sys, re, json, math, time, datetime, base64
import html as html_mod
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests, urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import jsbeautifier; HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

try:
    import pyjsparser; HAS_AST = True
except ImportError:
    HAS_AST = False

DOMAIN_BLACKLIST = ["googletagmanager.com","google-analytics.com","googleapis.com","gstatic.com","doubleclick.net","googlesyndication.com","facebook.net","fbcdn.net","connect.facebook.net","youtube.com","ytimg.com","twitter.com","twimg.com","cdn.jsdelivr.net","cdnjs.cloudflare.com","unpkg.com","jquery.com","jqueryui.com","bootstrapcdn.com","fontawesome.com","hotjar.com","intercom.io","zendesk.com","newrelic.com","bugsnag.com","sentry.io","segment.com","mixpanel.com","amplitude.com","cloudflare.com","akamai.net","akamaized.net","wp-includes","wp-content/plugins","recaptcha","captcha","linkedin.com","instagram.com","tiktok.com","snapchat.com"]
HIGH_PRIORITY_KEYWORDS = ["config","env","setting","setup","app.","main.","init","secret","key","auth","api","credential","token","private","db.","database","connection","deploy","prod","production","backend","server"]
HIDDEN_ASSETS = [".env", ".env.local", ".env.production", ".env.development", ".env.backup", ".env.bak", ".env.old", ".env.example", "config.json", "config.js", "config.yaml", "config.yml", "config.php", "configuration.json", "app.config.json", "settings.json", "settings.py", "local_settings.py", "database.yml", "database.json", "db.json", "db.config.js", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.json", "composer.lock", "requirements.txt", "Pipfile", "Pipfile.lock", "package.json.bak", "config.json.bak", "backup.sql", "backup.zip", "database.sql", ".git/config", ".git/HEAD", "web.config", "app.yaml", "app.yml", "docker-compose.yml", "docker-compose.yaml", "kubernetes.yml", ".dockerenv", ".travis.yml", ".circleci/config.yml", "Jenkinsfile", ".github/workflows/deploy.yml", "credentials.json", "service-account.json", "gcloud-key.json", "firebase.json", ".firebaserc", "serverless.yml", "terraform.tfvars", "api-keys.txt", "secrets.txt", "passwords.txt", "keys.json", "tokens.json", "auth.json"]

FALSE_POSITIVE_CONTEXT = [r"placeholder",r"example",r"sample",r"demo",r"fake",r"console\.log",r"console\.warn",r"console\.error",r"//\s*todo",r"//\s*fixme",r"//\s*test",r"//\s*mock",r"unittest",r"spec\.",r"describe\(",r"it\(",r"test\(",r"\.test\.",r"\.spec\.",r"__test__",r"documentation",r"readme",r"comment",r"your[_\-\s]?key",r"insert[_\-\s]?here",r"replace[_\-\s]?me"]
FP_COMPILED = [re.compile(p, re.IGNORECASE) for p in FALSE_POSITIVE_CONTEXT]

SECRET_PATTERNS = [
    {"name":"AWS Access Key ID", "svc":"AWS", "severity":"CRITICAL", "pattern":r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"},
    {"name":"AWS Secret Access Key", "svc":"AWS", "severity":"CRITICAL", "pattern":r"(?i)(?:aws[_\-\s]?secret|secret[_\-\s]?access[_\-\s]?key)['\"\s]*[:=]['\"\s]*([A-Za-z0-9/+=]{40})"},
    {"name":"AWS S3 Bucket URL", "svc":"AWS", "severity":"HIGH", "pattern":r"https?://([a-z0-9\-\.]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"},
    {"name":"Google API Key", "svc":"Google", "severity":"HIGH", "pattern":r"AIza[0-9A-Za-z\-_]{35}"},
    {"name":"Google OAuth Token", "svc":"Google", "severity":"HIGH", "pattern":r"ya29\.[0-9A-Za-z\-_]{50,}"},
    {"name":"Google Service Account", "svc":"Google", "severity":"CRITICAL", "pattern":r'"type"\s*:\s*"service_account"'},
    {"name":"GitHub PAT (Classic)", "svc":"GitHub", "severity":"CRITICAL", "pattern":r"ghp_[0-9A-Za-z]{36}"},
    {"name":"GitHub Fine-grained PAT", "svc":"GitHub", "severity":"CRITICAL", "pattern":r"github_pat_[A-Za-z0-9_]{82}"},
    {"name":"Stripe Secret Key (Live)", "svc":"Stripe", "severity":"CRITICAL", "pattern":r"sk_live_[0-9a-zA-Z]{24,}"},
    {"name":"Slack Bot Token", "svc":"Slack", "severity":"HIGH", "pattern":r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}"},
    {"name":"OpenAI API Key", "svc":"OpenAI", "severity":"CRITICAL", "pattern":r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"},
    {"name":"Private Key Block", "svc":"Crypto", "severity":"CRITICAL", "pattern":r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"},
]

NULL_VALUES = {"null","undefined","none","false","true","your_api_key","your_secret","your_token","xxxxxxxxxxx","xxxxxxxxxxxxxxxx","0000000000000000","insert_key_here","api_key_here","example","changeme","replace_me","dummy","<api_key>","<secret>","<token>","xxx","","test","sample","placeholder","todo","fixme","n/a","na","empty","string","value"}
SEVERITY_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
ENTROPY_GOLD = 4.5
ENTROPY_WARN = 3.5

def shannon_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def entropy_label(val):
    e = shannon_entropy(val)
    if e >= ENTROPY_GOLD: return f"{e:.2f} (GOLD)", True
    if e >= ENTROPY_WARN: return f"{e:.2f}", False
    return f"{e:.2f}", False

class Deobfuscator:
    B64_RE = re.compile(r"['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]")
    CHARCODE_RE = re.compile(r"String\.fromCharCode\s*\(([0-9,\s]+)\)", re.IGNORECASE)
    ATOB_RE    = re.compile(r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]", re.IGNORECASE)
    def _safe_b64(self, s):
        try:
            pad = s + "=" * (-len(s) % 4)
            dec = base64.b64decode(pad).decode("utf-8", errors="replace")
            if any(c < " " and c not in "\n\r\t" for c in dec): return None
            return dec
        except Exception: return None
    def deobfuscate(self, code, log_cb=None):
        extra = []
        for m in self.ATOB_RE.finditer(code):
            dec = self._safe_b64(m.group(1))
            if dec and len(dec) >= 8: extra.append(f'/* DEOB:atob => {dec[:300]} */')
        for m in self.B64_RE.finditer(code):
            val = m.group(1)
            if len(val) % 4 == 0 or len(val) % 4 == 3:
                dec = self._safe_b64(val)
                if dec and shannon_entropy(dec) > 2.5 and len(dec) >= 10: extra.append(f'/* DEOB:b64 => {dec[:300]} */')
        if extra:
            return code + "\n" + "\n".join(extra)
        return code

DEOBFUSCATOR = Deobfuscator()

class ASTAnalyzer:
    KEY_VAR_NAMES = re.compile(r"(?i)\b(?:api[_\-]?key|secret|token|password|credential|auth|access[_\-]?key|private[_\-]?key|client[_\-]?secret)\b")
    VAR_ASSIGN_RE = re.compile(r"(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:(['\"])([^'\"]{8,})\2)", re.MULTILINE)
    def analyze(self, code, source, log_cb=None):
        findings = []
        for m in self.VAR_ASSIGN_RE.finditer(code):
            var_name, _, val = m.group(1), m.group(2), m.group(3)
            if self.KEY_VAR_NAMES.search(var_name) and val.lower() not in NULL_VALUES:
                if len(val) >= 12 and len(set(val)) >= 4:
                    elabel, ig = entropy_label(val)
                    findings.append({"name": f"AST: Variable '{var_name}'","svc": "AST","severity": "HIGH" if ig else "MEDIUM","value": val[:150],"source": source,"context": m.group(0)[:120],"entropy": elabel,"is_golden": ig,"validation":"—","ast_source":True})
        return findings

AST_ANALYZER = ASTAnalyzer()

def contextual_filter(val, context):
    ctx_lower = context.lower()
    if val.lower() in NULL_VALUES: return "reject"
    for pat in FP_COMPILED:
        if pat.search(ctx_lower): return "downgrade"
    if len(set(val)) < 4: return "reject"
    if re.fullmatch(r"\d+", val): return "reject"
    if len(val) < 10: return "downgrade"
    return "keep"

def validate_token(finding):
    name = finding["name"]; val = finding["value"].rstrip("…")
    try:
        if "GitHub" in name:
            r = requests.get("https://api.github.com/user", headers={"Authorization":f"token {val}"},timeout=5)
            if r.status_code==200: return f"VALID - {r.json().get('login','?')}"
            return f"INVALID ({r.status_code})"
        elif "OpenAI" in name:
            r = requests.get("https://api.openai.com/v1/models", headers={"Authorization":f"Bearer {val}"},timeout=5)
            return "VALID" if r.status_code==200 else f"INVALID ({r.status_code})"
    except Exception: pass
    return "—"

class Scanner:
    def __init__(self, log_cb, progress_cb):
        self.log = log_cb; self.prog = progress_cb; self.stop_flag = False; self.results = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})

    def crawl(self, target_url, timeout, recursive_depth=1):
        self.log("INFO", "[*] Crawling: " + target_url)
        js_urls, inlines, map_urls = [], [], []
        visited = set()
        def _crawl(url, depth):
            if url in visited or depth < 0 or self.stop_flag: return
            visited.add(url)
            try:
                r = self.session.get(url, timeout=timeout, verify=False); r.raise_for_status()
                soup = BeautifulSoup(r.text, "html.parser"); thost = urlparse(target_url).netloc
                for tag in soup.find_all("script"):
                    src = tag.get("src","").strip()
                    if src:
                        full = urljoin(url, src)
                        if full not in js_urls: js_urls.append(full)
                        mh = f"{full}.map"
                        if mh not in map_urls: map_urls.append(mh)
                    elif tag.string and tag.string.strip():
                        inlines.append(tag.string.strip())
                        sm = re.search(r"//# sourceMappingURL=([^\s]+)", tag.string)
                        if sm:
                            mu = urljoin(url, sm.group(1))
                            if mu not in map_urls: map_urls.append(mu)
                if depth > 0:
                    for a in soup.find_all("a", href=True):
                        href = urljoin(url, a["href"])
                        if urlparse(href).netloc == thost and href not in visited: _crawl(href, depth-1)
            except Exception as e: self.log("WARN", "  Crawl fejl " + url + ": " + str(e))
        _crawl(target_url, recursive_depth)
        priority, normal, skipped = [], [], []
        thost = urlparse(target_url).netloc
        for url in js_urls:
            p = urlparse(url); h = p.netloc; path = p.path.lower()
            if any(b in h or b in path for b in DOMAIN_BLACKLIST): skipped.append(url); continue
            (priority if (thost in h or h in thost or any(k in path for k in HIGH_PRIORITY_KEYWORDS)) else normal).append(url)
        ordered = priority + normal
        self.log("INFO", f"  JS filer: {len(ordered)} | Inline: {len(inlines)} | Maps: {len(map_urls)}")
        return ordered, inlines, map_urls

    def fetch_all(self, urls, timeout, workers):
        if not urls: return {}
        self.log("INFO", f"  Downloader {len(urls)} filer...")
        out = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fmap = {ex.submit(self._fetch_one, u, timeout): u for u in urls}
            for fut in as_completed(fmap):
                if self.stop_flag: break
                out[fmap[fut]] = fut.result()
        return out

    def _fetch_one(self, url, timeout):
        try:
            r = self.session.get(url, timeout=timeout, verify=False); r.raise_for_status(); return r.text
        except Exception as e:
            self.log("WARN", f"  Fejl {url.split('/')[-1][:35]}: {e}"); return ""

    def discover_hidden_assets(self, target_url, timeout):
        self.log("INFO", "[*] Leder efter skjulte filer...")
        base = target_url.rstrip("/")
        interesting = []
        def _probe(path):
            url = f"{base}/{path.lstrip('/')}"
            try:
                r = self.session.get(url, timeout=timeout//2, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10: return url, r.text
            except Exception: pass
            return url, None
        with ThreadPoolExecutor(max_workers=10) as ex:
            fmap = {ex.submit(_probe, path): path for path in HIDDEN_ASSETS}
            for fut in as_completed(fmap):
                if self.stop_flag: break
                url, content = fut.result()
                if content:
                    fname = fmap[fut]
                    interesting.append((url, content, fname))
                    self.log("CRIT", f"  FUNDET: {fname} ({len(content)} bytes)")
        self.log("INFO", f"  Skjulte filer: {len(interesting)} fundet")
        return interesting

    def beautify(self, code):
        if not HAS_BEAUTIFIER or len(code) > 3_000_000: return code
        try:
            opts = jsbeautifier.default_options(); opts.unescape_strings = True; opts.wrap_line_length = 0
            return jsbeautifier.beautify(code, opts)
        except Exception: return code

    def scan_content(self, content, source):
        code = self.beautify(content)
        code = DEOBFUSCATOR.deobfuscate(code)
        found = []
        for pat in SECRET_PATTERNS:
            try: matches = re.findall(pat["pattern"], code, re.MULTILINE)
            except re.error: continue
            for m in matches:
                if self.stop_flag: break
                val = (m if isinstance(m,str) else m[0] if m else "").strip().strip("\"'")
                if not val or len(val) < 8 or len(set(val)) < 3 or val.isdigit(): continue
                idx = code.find(val); ctx = ""
                if idx != -1:
                    s = max(0, idx-50); e = min(len(code), idx+len(val)+50)
                    ctx = code[s:e].replace("\n"," ").strip()
                if contextual_filter(val, ctx) == "reject": continue
                elabel, ig = entropy_label(val)
                found.append({"name": pat["name"],"svc": pat["svc"],"severity": pat["severity"],"value": val[:150],"source": source,"context": ctx,"entropy": elabel,"is_golden": ig,"validation":"—"})

        ast_found = AST_ANALYZER.analyze(code, source)
        existing_vals = {f["value"][:40].lower() for f in found}
        for af in ast_found:
            if af["value"][:40].lower() not in existing_vals: found.append(af)
        return found

    def run(self, target_url, timeout=10, workers=10, do_validate=True, do_subdomain=True, do_hidden=True):
        self.results = []; self.stop_flag = False
        if not urlparse(target_url).scheme: target_url = "https://" + target_url
        ext_urls, inlines, map_urls = self.crawl(target_url, timeout)
        fetched = self.fetch_all(ext_urls, timeout, workers)

        all_findings = []
        total = len(inlines) + len(fetched)
        done = 0
        self.prog(0, max(total, 1))

        for i, code in enumerate(inlines, 1):
            if self.stop_flag: break
            found = self.scan_content(code, f"Inline #{i}")
            if found: self.log("HIGH", f"  Inline #{i}: {len(found)} fund")
            all_findings.extend(found); done += 1; self.prog(done, max(total, 1))

        for url, code in fetched.items():
            if self.stop_flag: break
            short = url.split("/")[-1][:45] or url[-45:]
            if code:
                found = self.scan_content(code, url)
                if found: self.log("HIGH", f"  {short}: {len(found)} fund")
                all_findings.extend(found)
            done += 1; self.prog(done, max(total, 1))

        if do_hidden:
            for url, content, fname in self.discover_hidden_assets(target_url, timeout):
                if self.stop_flag: break
                found = self.scan_content(content, f"[Hidden] {fname}")
                if found: self.log("CRIT", f"  {fname}: {len(found)} fund!")
                all_findings.extend(found)

        seen, unique = set(), []
        for f in all_findings:
            key = (f["name"], f["value"][:40].lower())
            if key not in seen: seen.add(key); unique.append(f)
        unique.sort(key=lambda x:(SEVERITY_ORDER.get(x["severity"],9), x["name"]))

        if do_validate:
            for f in unique:
                if f["severity"] in ("CRITICAL","HIGH") and not f.get("ast_source"):
                    self.log("INFO", f"  Tjekker {f['name']}...")
                    f["validation"] = validate_token(f)

        self.results = unique
        return unique

def generate_html_report(findings, target_url, counts, risk, ts):
    sev_badge = {"CRITICAL":"#FF2244","HIGH":"#FF8C00","MEDIUM":"#FFD700","LOW":"#00BFFF"}
    rows = ""
    for i, f in enumerate(findings, 1):
        color = sev_badge.get(f["severity"],"#888")
        gold = f.get("is_golden",False)
        ast_m = " [AST]" if f.get("ast_source") else ""
        src_name = html_mod.escape(f.get('source','').split('/')[-1][:35])
        gold_style = 'background:#1a1400;' if gold else ''
        gold_color = 'color:#FFD700' if gold else ''
        rows += f"""<tr style="{gold_style}"><td>{i}</td><td><span class="badge" style="background:{color}">{f['severity']}</span></td><td>{html_mod.escape(f['name'])}{ast_m}</td><td>{html_mod.escape(f.get('svc',''))}</td><td class="mono">{html_mod.escape(f.get('value',''))}</td><td class="mono small">{html_mod.escape(f.get('context',''))}</td><td style="{gold_color}">{html_mod.escape(f.get('entropy',''))}</td><td>{html_mod.escape(f.get('validation','—'))}</td><td class="small">{src_name}</td></tr>"""
    rc = "#FF2244" if risk>=70 else "#FF8C00" if risk>=40 else "#FFD700" if risk>=15 else "#00BFFF"
    return f"""<!DOCTYPE html><html lang="da"><head><meta charset="UTF-8"><title>JS Secret Hunter</title><style>body{{font-family:Consolas,monospace;background:#080812;color:#ccd;padding:20px}}table{{width:100%;border-collapse:collapse}}th{{background:#12121e;color:#00FF88;padding:8px;text-align:left}}td{{padding:6px;border-bottom:1px solid #1a1a2e}}.badge{{padding:2px 6px;border-radius:4px;color:#000;font-weight:bold}}.mono{{font-family:monospace}}.small{{font-size:11px;color:#556}}</style></head><body><h1>JS Secret Hunter</h1><p>Target: {html_mod.escape(target_url)} | {ts} | Risk: {risk}/100</p><table><thead><tr><th>#</th><th>Severity</th><th>Name</th><th>Service</th><th>Value</th><th>Context</th><th>Entropy</th><th>Validation</th><th>Source</th></tr></thead><tbody>{rows}</tbody></table></body></html>"""

if __name__ == "__main__":
    print("\n\033[38;2;0;255;255m[+] JS Secret Hunter v4 — CLI Edition\033[0m\n")

    target = input("\033[38;2;255;0;255mIndtast Target URL (f.eks. https://example.com): \033[0m").strip()
    if not target: sys.exit(1)

    def log(sev, msg):
        colors = {"INFO":"\033[38;2;153;170;187m", "WARN":"\033[38;2;255;140;0m", "HIGH":"\033[38;2;255;140;0m", "CRIT":"\033[38;2;255;34;68m"}
        c = colors.get(sev, "\033[0m")
        print(c + msg + "\033[0m")

    def prog(done, total):
        pct = int(done/total*100) if total else 0
        sys.stdout.write(f"\r\033[38;2;0;255;136m[*] Fremskridt: {done}/{total} ({pct}%) \033[0m")
        sys.stdout.flush()

    scanner = Scanner(log, prog)
    print()
    findings = scanner.run(target, timeout=10, workers=10, do_validate=True, do_subdomain=True, do_hidden=True)
    print("\n")

    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
    risk = min(100,counts.get("CRITICAL",0)*30+counts.get("HIGH",0)*15+counts.get("MEDIUM",0)*5+counts.get("LOW",0)*1)

    print("\033[38;2;0;255;255m[+] Scan fuldført! Fandt " + str(len(findings)) + " tokens. (Risk: " + str(risk) + "/100)\033[0m")
    for f in findings:
        col = "\033[38;2;255;34;68m" if f["severity"]=="CRITICAL" else "\033[38;2;255;140;0m" if f["severity"]=="HIGH" else "\033[38;2;255;215;0m"
        print(col + "[" + f['severity'] + "]\033[0m " + f['name'] + " -> \033[38;2;0;255;136m" + f['value'] + "\033[0m (" + str(f.get('validation','—')) + ")")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = urlparse(target).netloc.replace(".","_")
    base = "jsh_" + domain + "_" + ts
    with open(base + ".html", "w", encoding="utf-8") as fh:
        fh.write(generate_html_report(findings, target, counts, risk, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    print("\n\033[38;2;0;255;255m[*] HTML Rapport gemt i: " + base + ".html\033[0m")
