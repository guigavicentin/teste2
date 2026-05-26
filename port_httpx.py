#!/usr/bin/env python3
"""
recon_scan.py — Recon + Port Scan + HTTP Check + Nuclei Prep
Bug Bounty Edition

Uso:
  # Domínio completo (subfinder + assetfinder + chaos + github)
  python3 recon_scan.py -d gocache.com.br

  # Domínio individual (só esse host, sem enumeração)
  python3 recon_scan.py --single sub.gocache.com.br

  # Lista de domínios
  python3 recon_scan.py -d gocache.com.br -o ./output --threads 100

Tokens (via variável de ambiente — não passe pelo script):
  export CHAOS_KEY=xxx
  export GITHUB_TOKEN=ghp_xxx
"""

import argparse
import os
import sys
import subprocess
import shutil
import time
from datetime import datetime
from pathlib import Path

# ── Cores ────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"
B="\033[94m"; C="\033[96m"; W="\033[0m"; BOLD="\033[1m"

def banner():
    print(f"""{C}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  Recon + Scan + Nuclei Prep — Bug Bounty Edition
{W}""")

def log_info(msg):  print(f"{B}[*]{W} {msg}")
def log_ok(msg):    print(f"{G}[+]{W} {msg}")
def log_warn(msg):  print(f"{Y}[!]{W} {msg}")
def log_fail(msg):  print(f"{R}[-]{W} {msg}")
def log_sec(msg):   print(f"\n{BOLD}{C}{'═'*10} {msg} {'═'*10}{W}")

def has_tool(name):
    return shutil.which(name) is not None

def run(cmd, output_file=None, shell=False, timeout=600):
    """Executa comando e opcionalmente salva output"""
    try:
        result = subprocess.run(
            cmd if shell else cmd.split() if isinstance(cmd, str) else cmd,
            capture_output=True, text=True,
            timeout=timeout, shell=shell
        )
        if output_file and result.stdout.strip():
            Path(output_file).write_text(result.stdout)
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        log_warn(f"Timeout: {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
        return "", 1
    except Exception as e:
        log_warn(f"Erro: {e}")
        return "", 1

def count_lines(filepath):
    try:
        return sum(1 for line in open(filepath) if line.strip())
    except:
        return 0

def write_lines(filepath, lines):
    unique = sorted(set(l.strip() for l in lines if l.strip()))
    Path(filepath).write_text("\n".join(unique) + "\n" if unique else "")
    return len(unique)

def read_lines(filepath):
    try:
        return [l.strip() for l in open(filepath) if l.strip()]
    except:
        return []

# ─────────────────────────────────────────────────────────────────
# ETAPA 1 — Enumeração de subdomínios
# ─────────────────────────────────────────────────────────────────
def enumerate_subdomains(domain, outdir, single=False):
    log_sec("ETAPA 1 — Subdomínios")

    subs_file = outdir / "subdomains.txt"

    # Modo single — só o próprio host
    if single:
        write_lines(subs_file, [domain])
        log_ok(f"Modo single: usando apenas {domain}")
        return subs_file

    all_subs = []

    # subfinder
    if has_tool("subfinder"):
        log_info("Rodando subfinder...")
        out, _ = run(["subfinder", "-d", domain, "-silent"])
        lines = [l for l in out.splitlines() if l.strip()]
        all_subs.extend(lines)
        write_lines(outdir / "subfinder.txt", lines)
        log_ok(f"subfinder: {len(lines)} subdomínios")
    else:
        log_warn("subfinder não encontrado — pulando")

    # assetfinder
    if has_tool("assetfinder"):
        log_info("Rodando assetfinder...")
        out, _ = run(["assetfinder", "--subs-only", domain])
        lines = [l for l in out.splitlines() if l.strip()]
        all_subs.extend(lines)
        write_lines(outdir / "assetfinder.txt", lines)
        log_ok(f"assetfinder: {len(lines)} subdomínios")
    else:
        log_warn("assetfinder não encontrado — pulando")

    # chaos — requer CHAOS_KEY
    if has_tool("chaos"):
        chaos_key = os.environ.get("CHAOS_KEY", "")
        if chaos_key:
            log_info("Rodando chaos...")
            out, _ = run(["chaos", "-d", domain, "-silent",
                          "-key", chaos_key])
            lines = [l for l in out.splitlines() if l.strip()]
            all_subs.extend(lines)
            write_lines(outdir / "chaos.txt", lines)
            log_ok(f"chaos: {len(lines)} subdomínios")
        else:
            log_warn("CHAOS_KEY não definida — export CHAOS_KEY=xxx")
    else:
        log_warn("chaos não encontrado — pulando")

    # github-subdomains — requer GITHUB_TOKEN
    if has_tool("github-subdomains"):
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if github_token:
            log_info("Rodando github-subdomains...")
            out, _ = run(["github-subdomains", "-d", domain,
                          "-t", github_token])
            lines = [l for l in out.splitlines() if l.strip()]
            all_subs.extend(lines)
            write_lines(outdir / "github.txt", lines)
            log_ok(f"github-subdomains: {len(lines)} subdomínios")
        else:
            log_warn("GITHUB_TOKEN não definida — export GITHUB_TOKEN=ghp_xxx")
    else:
        log_warn("github-subdomains não encontrado — pulando")

    # Deduplicação final
    total = write_lines(subs_file, all_subs)
    log_ok(f"Total únicos: {total} subdomínios → {subs_file}")
    return subs_file

# ─────────────────────────────────────────────────────────────────
# ETAPA 2 — Resolução DNS + IPs
# ─────────────────────────────────────────────────────────────────
def resolve_ips(subs_file, outdir):
    log_sec("ETAPA 2 — Resolução DNS e IPs")

    ips_raw = []
    dns_resolved = outdir / "dns_resolved.txt"
    ips_file = outdir / "ips.txt"

    if has_tool("dnsx"):
        log_info("Resolvendo com dnsx...")
        # -a retorna registros A, -resp mostra a resposta (suportado na maioria das versões)
        # Tenta com -resp primeiro, fallback sem ele
        out, rc = run(["dnsx", "-l", str(subs_file), "-a", "-resp", "-silent", "-no-color"])
        if not out.strip():
            out, rc = run(["dnsx", "-l", str(subs_file), "-a", "-silent", "-no-color"])
        Path(dns_resolved).write_text(out + "\n")

        import re
        # Remove ANSI color codes do output do dnsx antes de parsear
        ansi_escape = re.compile(r'\[[0-9;]*m')
        for line in out.splitlines():
            clean = ansi_escape.sub('', line)
            matches = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', clean)
            if not matches:
                matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', clean)
            for ip in matches:
                parts = list(map(int, ip.split(".")))
                if parts[0] == 127 or (parts[0] == 169 and parts[1] == 254):
                    continue
                ips_raw.append(ip)
        log_ok(f"dnsx resolveu {count_lines(dns_resolved)} entradas")
    else:
        log_warn("dnsx não encontrado — usando dig...")
        import subprocess, re
        results = []
        for sub in read_lines(subs_file):
            out, _ = run(["dig", "+short", "A", sub])
            for line in out.splitlines():
                line = line.strip()
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    ips_raw.append(line)
                    results.append(f"{sub} [{line}]")
        Path(dns_resolved).write_text("\n".join(results) + "\n")

    total = write_lines(ips_file, ips_raw)
    log_ok(f"IPs únicos: {total} → {ips_file}")
    return ips_file

# ─────────────────────────────────────────────────────────────────
# ETAPA 3 — Nmap
# ─────────────────────────────────────────────────────────────────
def run_nmap(ips_file, outdir):
    log_sec("ETAPA 3 — Nmap Port Scan")

    nmap_dir = outdir / "nmap"
    nmap_dir.mkdir(exist_ok=True)
    nmap_base = str(nmap_dir / "scan")
    ports_all  = outdir / "all_open_ports.txt"
    ports_detail = outdir / "ports_detail.txt"

    if not has_tool("nmap"):
        log_warn("nmap não encontrado — pulando")
        return nmap_dir

    total_ips = count_lines(ips_file)
    log_info(f"Rodando nmap -sS -sV -p- -T4 em {total_ips} IPs...")
    log_warn("Pode demorar dependendo da quantidade de IPs.")

    run(["nmap", "-sS", "-sV", "-p-", "-T4",
         "--open", "-iL", str(ips_file),
         "-oA", nmap_base],
        timeout=7200)

    gnmap = Path(nmap_base + ".gnmap")
    if not gnmap.exists():
        log_warn("Arquivo gnmap não gerado.")
        return nmap_dir

    log_ok(f"Nmap concluído → {nmap_dir}/")

    # Extrai portas únicas
    import re
    all_ports = set()
    detail_lines = []

    for line in gnmap.read_text().splitlines():
        if "open" not in line or not line.startswith("Host:"):
            continue
        parts = line.split()
        ip = parts[1]
        for token in parts:
            m = re.match(r'(\d+)/open', token)
            if m:
                port = m.group(1)
                all_ports.add(port)
                detail_lines.append(f"{ip}:{port}")

    ports_all.write_text("\n".join(sorted(all_ports, key=int)) + "\n")
    ports_detail.write_text("\n".join(sorted(detail_lines)) + "\n")

    log_ok(f"Portas abertas únicas: {len(all_ports)} → {ports_all}")
    log_ok(f"host:porta detalhado  → {ports_detail}")

    return nmap_dir

# ─────────────────────────────────────────────────────────────────
# ETAPA 4 — httpx
# ─────────────────────────────────────────────────────────────────
def run_httpx(subs_file, outdir, threads=50):
    log_sec("ETAPA 4 — HTTP/HTTPS com httpx")

    http_alive  = outdir / "http_alive.txt"
    http_detail = outdir / "http_detail.txt"

    if has_tool("httpx"):
        log_info("Rodando httpx (detalhe)...")
        run(["httpx", "-l", str(subs_file),
             "-silent", "-threads", str(threads),
             "-status-code", "-title", "-tech-detect",
             "-follow-redirects", "-o", str(http_detail)])

        log_info("Rodando httpx (URLs vivas)...")
        run(["httpx", "-l", str(subs_file),
             "-silent", "-threads", str(threads),
             "-follow-redirects", "-o", str(http_alive)])

        total = count_lines(http_alive)
        log_ok(f"HTTP/HTTPS vivos: {total} → {http_alive}")
    else:
        log_warn("httpx não encontrado — usando curl fallback...")
        import subprocess
        alive = []
        for sub in read_lines(subs_file):
            for proto in ["https", "http"]:
                url = f"{proto}://{sub}"
                r = subprocess.run(
                    ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                     "--connect-timeout", "5", "--max-time", "8", url],
                    capture_output=True, text=True)
                if r.stdout.strip() not in ["000", ""]:
                    alive.append(url)
                    break
        write_lines(http_alive, alive)
        log_ok(f"HTTP/HTTPS vivos: {len(alive)}")

    return http_alive

# ─────────────────────────────────────────────────────────────────
# ETAPA 5 — Separar targets para Nuclei
# ─────────────────────────────────────────────────────────────────
def prepare_nuclei_targets(http_alive, nmap_dir, outdir):
    log_sec("ETAPA 5 — Preparação Nuclei Targets")

    nuclei_dir = outdir / "nuclei_targets"
    nuclei_dir.mkdir(exist_ok=True)

    # HTTP/HTTPS
    import shutil as sh
    if http_alive.exists():
        sh.copy(http_alive, nuclei_dir / "http_https.txt")
        log_ok(f"HTTP/HTTPS → nuclei_targets/http_https.txt ({count_lines(http_alive)} hosts)")

    # Serviços não-HTTP por porta
    PORT_SERVICES = {
        21:    "ftp",
        22:    "ssh",
        23:    "telnet",
        25:    "smtp",
        110:   "pop3",
        143:   "imap",
        3306:  "mysql",
        5432:  "postgres",
        6379:  "redis",
        27017: "mongodb",
        3389:  "rdp",
        5900:  "vnc",
        11211: "memcached",
        9200:  "elasticsearch",
        2181:  "zookeeper",
        5672:  "rabbitmq",
        8161:  "activemq",
        9092:  "kafka",
    }

    gnmap = nmap_dir / "scan.gnmap"
    if not gnmap.exists():
        log_warn("scan.gnmap não encontrado — pulando separação por serviço")
        return nuclei_dir

    import re
    # Monta dict port -> [ips]
    port_hosts = {p: [] for p in PORT_SERVICES}

    for line in gnmap.read_text().splitlines():
        if "open" not in line or not line.startswith("Host:"):
            continue
        parts = line.split()
        ip = parts[1]
        for token in parts:
            m = re.match(r'(\d+)/open', token)
            if m:
                port = int(m.group(1))
                if port in PORT_SERVICES:
                    port_hosts[port].append(ip)

    for port, svc in PORT_SERVICES.items():
        hosts = sorted(set(port_hosts[port]))
        if not hosts:
            continue
        target_file = nuclei_dir / f"{svc}_{port}.txt"
        # Formato aceito pelo nuclei para serviços de rede
        lines = [f"{svc}://{ip}:{port}" for ip in hosts]
        target_file.write_text("\n".join(lines) + "\n")
        log_ok(f"{svc} (:{port}): {len(hosts)} hosts → nuclei_targets/{target_file.name}")

    return nuclei_dir

# ─────────────────────────────────────────────────────────────────
# ETAPA 6 — Gerar nuclei_commands.sh
# ─────────────────────────────────────────────────────────────────
def generate_nuclei_commands(nuclei_dir, outdir, domain):
    log_sec("ETAPA 6 — Gerando nuclei_commands.sh")

    results_dir = outdir / "nuclei_results"
    cmds_file   = outdir / "nuclei_commands.sh"

    PORT_TEMPLATES = {
        "ftp":           ["network/ftp-anonymous-login.yaml",
                          "network/ftp-weak-credentials.yaml"],
        "ssh":           ["network/ssh-auth-methods.yaml",
                          "network/deprecated-ssh-cryptographic-settings.yaml"],
        "smtp":          ["network/smtp-open-relay.yaml",
                          "network/smtp-user-enumeration.yaml"],
        "mysql":         ["network/mysql-empty-password.yaml",
                          "network/mysql-native-password.yaml"],
        "postgres":      ["network/postgres-unauth.yaml"],
        "redis":         ["network/redis-unauthenticated-access.yaml"],
        "mongodb":       ["network/mongodb-unauth.yaml"],
        "rdp":           ["network/rdp-detect.yaml",
                          "network/bluekeep.yaml"],
        "elasticsearch": ["exposures/configs/elastic-kibana-unauth.yaml",
                          "network/elasticsearch-unauth.yaml"],
        "memcached":     ["network/memcached-unauth.yaml"],
        "vnc":           ["network/vnc-detect.yaml"],
        "zookeeper":     ["network/zookeeper-unauth.yaml"],
        "rabbitmq":      ["network/rabbitmq-management-unauth.yaml"],
    }

    lines = [
        "#!/usr/bin/env bash",
        f"# nuclei_commands.sh — gerado em {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"# Alvo: {domain}",
        "",
        f'RESULTS="{results_dir}"',
        'mkdir -p "$RESULTS"',
        "",
    ]

    # HTTP/HTTPS
    http_file = nuclei_dir / "http_https.txt"
    if http_file.exists() and count_lines(http_file) > 0:
        lines += [
            "# ── HTTP/HTTPS ──────────────────────────────────────────────",
            "echo '[*] Nuclei em HTTP/HTTPS...'",
            f'nuclei \\',
            f'  -l "{http_file}" \\',
            f'  -t exposures/ -t vulnerabilities/ -t misconfiguration/ \\',
            f'  -t cves/ -t technologies/ -t takeovers/ \\',
            f'  -severity low,medium,high,critical \\',
            f'  -threads 25 \\',
            f'  -o "$RESULTS/http_findings.txt" \\',
            f'  -stats',
            "",
        ]

    # Serviços não-HTTP
    for target_file in sorted(nuclei_dir.glob("*.txt")):
        if target_file.name == "http_https.txt":
            continue
        if count_lines(target_file) == 0:
            continue

        svc = target_file.stem.split("_")[0]
        templates = PORT_TEMPLATES.get(svc, [f"network/{svc}-*"])
        tpl_args = " \\\n  ".join([f"-t {t}" for t in templates])

        lines += [
            f"# ── {svc.upper()} ──────────────────────────────────────────────",
            f"echo '[*] Nuclei em {svc.upper()}...'",
            f'[ -f "{target_file}" ] && nuclei \\',
            f'  -l "{target_file}" \\',
            f'  {tpl_args} \\',
            f'  -o "$RESULTS/{svc}_findings.txt"',
            "",
        ]

    lines += [
        'echo "[+] Nuclei concluído. Resultados em: $RESULTS/"',
    ]

    cmds_file.write_text("\n".join(lines) + "\n")
    cmds_file.chmod(0o755)
    log_ok(f"Comandos nuclei salvos → {cmds_file}")
    return cmds_file

# ─────────────────────────────────────────────────────────────────
# SUMÁRIO
# ─────────────────────────────────────────────────────────────────
def print_summary(domain, outdir, cmds_file, start_time):
    log_sec("SUMÁRIO")

    elapsed = int(time.time() - start_time)
    mins, secs = divmod(elapsed, 60)

    subs  = count_lines(outdir / "subdomains.txt")
    ips   = count_lines(outdir / "ips.txt")
    http  = count_lines(outdir / "http_alive.txt")
    ports = count_lines(outdir / "all_open_ports.txt")

    print(f"""
{BOLD}  Domínio:             {domain}
  Tempo total:         {mins}m {secs}s
  Subdomínios únicos:  {subs}
  IPs únicos:          {ips}
  HTTP/HTTPS vivos:    {http}
  Portas abertas:      {ports}{W}

{G}  Estrutura de output:{W}
  {outdir}/
  ├── subdomains.txt        → subdomínios únicos
  ├── ips.txt               → IPs únicos
  ├── dns_resolved.txt      → resolução DNS
  ├── all_open_ports.txt    → todas as portas abertas
  ├── ports_detail.txt      → host:porta detalhado
  ├── http_alive.txt        → URLs vivas (pronto para nuclei)
  ├── http_detail.txt       → httpx detalhado
  ├── nmap/                 → .nmap / .gnmap / .xml
  ├── nuclei_targets/       → alvos separados por serviço
  └── nuclei_commands.sh    → execute para rodar nuclei
""")
    log_ok(f"Para rodar nuclei: bash {cmds_file}")

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Recon + Scan + Nuclei Prep — Bug Bounty Edition"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-d", "--domain",
        help="Domínio alvo — enumeração completa (subfinder, assetfinder, chaos, github)")
    mode.add_argument("--single",
        help="Host individual — pula enumeração, testa só esse host")

    parser.add_argument("-o", "--output",
        help="Diretório de output (padrão: recon_<domain>_<timestamp>)")
    parser.add_argument("-t", "--threads",
        type=int, default=50, help="Threads para httpx (padrão: 50)")
    parser.add_argument("--skip-nmap",
        action="store_true", help="Pular nmap (mais rápido)")
    parser.add_argument("--skip-enum",
        action="store_true", help="Pular enumeração (usa subdomains.txt existente)")

    args = parser.parse_args()

    start_time = time.time()
    domain = args.domain or args.single
    single = bool(args.single)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    outdir = Path(args.output) if args.output else Path(f"recon_{domain}_{timestamp}")
    outdir.mkdir(parents=True, exist_ok=True)

    log_info(f"Domínio: {domain}")
    log_info(f"Modo:    {'single host' if single else 'enumeração completa'}")
    log_info(f"Output:  {outdir}")
    log_info(f"Início:  {datetime.now().strftime('%H:%M:%S')}")

    # Avisa sobre tokens
    if not single:
        if not os.environ.get("CHAOS_KEY"):
            log_warn("CHAOS_KEY não definida — chaos será pulado")
        if not os.environ.get("GITHUB_TOKEN"):
            log_warn("GITHUB_TOKEN não definida — github-subdomains será pulado")

    # Etapas
    subs_file  = enumerate_subdomains(domain, outdir, single=single)
    ips_file   = resolve_ips(subs_file, outdir)
    nmap_dir   = outdir / "nmap"

    if not args.skip_nmap:
        nmap_dir = run_nmap(ips_file, outdir)
    else:
        log_warn("Nmap pulado (--skip-nmap)")
        nmap_dir.mkdir(exist_ok=True)

    http_alive   = run_httpx(subs_file, outdir, args.threads)
    nuclei_dir   = prepare_nuclei_targets(http_alive, nmap_dir, outdir)
    cmds_file    = generate_nuclei_commands(nuclei_dir, outdir, domain)

    print_summary(domain, outdir, cmds_file, start_time)


if __name__ == "__main__":
    main()
