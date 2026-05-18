#!/usr/bin/env python3
"""
recon.py - Reconhecimento automatizado de subdomínios
Ferramentas: chaos, github-subdomains, subfinder, assetfinder, nmap, httpx
"""

import subprocess
import os
import sys
import re
import json
import shutil
import argparse
from pathlib import Path
from datetime import datetime

# ──────────────────────────────────────────────
# CONFIGURAÇÕES
# ──────────────────────────────────────────────
PORTS = "80,81,3000,3001,8443,10000,9000,9443,443,8080,8000,6885,4443,2075,2076,6443,3868,3366,9091,5900,8081,6000,8181,3306,5000,4000,5432,15672,9999,161,4044,7077"
HTTPX_THREADS = 80

TOOLS_REQUIRED = ["subfinder", "assetfinder", "nmap", "httpx"]
TOOLS_OPTIONAL = ["chaos", "github-subdomains"]


# ──────────────────────────────────────────────
# UTILIDADES
# ──────────────────────────────────────────────

def banner():
    print("""
\033[1;32m
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
  Subdomain Recon + Nmap + HTTPX
""")


def log(msg, level="INFO"):
    colors = {"INFO": "\033[1;34m", "OK": "\033[1;32m", "WARN": "\033[1;33m", "ERR": "\033[1;31m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{c}[{level}] {ts} {msg}{reset}")


def run_cmd(cmd, output_file=None, timeout=300):
    """Executa comando e retorna stdout como string."""
    log(f"$ {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            log(f"stderr: {result.stderr[:300]}", "WARN")
        if output_file and out:
            Path(output_file).write_text(out + "\n")
        return out
    except subprocess.TimeoutExpired:
        log(f"Timeout ao executar: {cmd}", "WARN")
        return ""
    except Exception as e:
        log(f"Erro: {e}", "ERR")
        return ""


def tool_available(name):
    return shutil.which(name) is not None


def check_tools():
    missing_req = [t for t in TOOLS_REQUIRED if not tool_available(t)]
    missing_opt = [t for t in TOOLS_OPTIONAL if not tool_available(t)]

    if missing_req:
        log(f"Ferramentas obrigatórias não encontradas: {', '.join(missing_req)}", "ERR")
        log("Instale antes de continuar.", "ERR")
        sys.exit(1)

    if missing_opt:
        log(f"Ferramentas opcionais não encontradas (serão puladas): {', '.join(missing_opt)}", "WARN")

    log("Verificação de ferramentas OK", "OK")


def dedup_sort(lines):
    return sorted(set(l.strip().lower() for l in lines if l.strip()))


def write_lines(path, lines):
    Path(path).write_text("\n".join(lines) + "\n")
    log(f"Salvo: {path} ({len(lines)} entradas)", "OK")


# ──────────────────────────────────────────────
# COLETA DE SUBDOMÍNIOS
# ──────────────────────────────────────────────

def run_subfinder(domain, outdir):
    out = f"{outdir}/subfinder.txt"
    run_cmd(f"subfinder -d {domain} -silent -o {out}", timeout=180)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def run_assetfinder(domain, outdir):
    out = f"{outdir}/assetfinder.txt"
    run_cmd(f"assetfinder --subs-only {domain} > {out}", timeout=120)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def run_chaos(domain, outdir):
    if not tool_available("chaos"):
        return []
    chaos_key = os.environ.get("CHAOS_KEY", "")
    if not chaos_key:
        log("CHAOS_KEY não definido — pulando chaos", "WARN")
        return []
    out = f"{outdir}/chaos.txt"
    run_cmd(f"chaos -d {domain} -key {chaos_key} -silent -o {out}", timeout=120)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def run_github_subdomains(domain, outdir):
    if not tool_available("github-subdomains"):
        return []
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        log("GITHUB_TOKEN não definido — pulando github-subdomains", "WARN")
        return []
    out = f"{outdir}/github_subs.txt"
    run_cmd(f"github-subdomains -d {domain} -t {token} -o {out}", timeout=120)
    return Path(out).read_text().splitlines() if Path(out).exists() else []


def collect_subdomains(domain, outdir):
    log("=== COLETA DE SUBDOMÍNIOS ===")
    all_subs = []

    all_subs += run_subfinder(domain, outdir)
    log(f"subfinder: {len(all_subs)} até agora", "OK")

    tmp = run_assetfinder(domain, outdir)
    all_subs += tmp
    log(f"assetfinder: +{len(tmp)}", "OK")

    tmp = run_chaos(domain, outdir)
    all_subs += tmp
    log(f"chaos: +{len(tmp)}", "OK")

    tmp = run_github_subdomains(domain, outdir)
    all_subs += tmp
    log(f"github-subdomains: +{len(tmp)}", "OK")

    # Filtra só subdomínios do alvo
    subs = dedup_sort([s for s in all_subs if domain in s])
    subs_file = f"{outdir}/subs_domain.txt"
    write_lines(subs_file, subs)
    log(f"Total de subdomínios únicos: {len(subs)}", "OK")
    return subs_file, subs


# ──────────────────────────────────────────────
# NMAP
# ──────────────────────────────────────────────

def run_nmap(subs_file, outdir):
    log("=== NMAP ===")
    nmap_out = f"{outdir}/nmap_output.txt"
    nmap_gnmap = f"{outdir}/nmap_output.gnmap"

    cmd = (
        f"nmap -iL {subs_file} "
        f"-p {PORTS} "
        f"--open -T4 -n "
        f"-oG {nmap_gnmap} "
        f"-oN {nmap_out} "
        f"--max-retries 2 "
        f"--host-timeout 60s"
    )
    run_cmd(cmd, timeout=1800)

    if not Path(nmap_gnmap).exists():
        log("Nmap não gerou saída grepable", "WARN")
        return {}

    # Parse gnmap → {ip: [porta, ...]}
    results = {}
    for line in Path(nmap_gnmap).read_text().splitlines():
        if "Ports:" not in line:
            continue
        # Ex: Host: 1.2.3.4 (sub.domain.com)  Ports: 80/open/tcp...
        host_match = re.search(r"Host:\s+(\S+)", line)
        ports_match = re.findall(r"(\d+)/open/tcp", line)
        if host_match and ports_match:
            ip = host_match.group(1)
            results.setdefault(ip, set()).update(ports_match)

    log(f"Nmap encontrou {len(results)} hosts com portas abertas", "OK")
    return {k: sorted(v, key=int) for k, v in results.items()}


# ──────────────────────────────────────────────
# HTTPX
# ──────────────────────────────────────────────

def run_httpx(subs_file, outdir):
    log("=== HTTPX ===")
    alive_file = f"{outdir}/alive.txt"
    alive_json = f"{outdir}/alive_json.txt"

    # Roda httpx com saída JSON para parsear IPs e portas
    cmd = (
        f"httpx -l {subs_file} "
        f"-ports {PORTS} "
        f"-threads {HTTPX_THREADS} "
        f"-json "
        f"-o {alive_json}"
    )
    run_cmd(cmd, timeout=900)

    # Também salva formato simples
    cmd2 = (
        f"httpx -l {subs_file} "
        f"-ports {PORTS} "
        f"-threads {HTTPX_THREADS} "
        f"-o {alive_file}"
    )
    run_cmd(cmd2, timeout=900)

    return alive_file, alive_json


# ──────────────────────────────────────────────
# PARSE & CONSOLIDAÇÃO
# ──────────────────────────────────────────────

def parse_httpx_json(alive_json):
    """
    Retorna lista de dicts com: url, host, ip, port, scheme
    """
    entries = []
    if not Path(alive_json).exists():
        return entries

    for line in Path(alive_json).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            url    = obj.get("url", "")
            host   = obj.get("host", obj.get("input", ""))
            ip     = obj.get("a", [""])[0] if obj.get("a") else obj.get("ip", "")
            port   = str(obj.get("port", ""))
            scheme = obj.get("scheme", "http")
            if url:
                entries.append({"url": url, "host": host, "ip": ip, "port": port, "scheme": scheme})
        except json.JSONDecodeError:
            pass

    return entries


def build_output_files(entries, nmap_results, outdir):
    """
    Gera os arquivos finais de saída.
    """
    log("=== GERANDO ARQUIVOS DE SAÍDA ===")

    # ── 1. Subdomínios ativos + portas (ex: sub.domain.com:80)
    sub_ports = set()
    for e in entries:
        host = e["host"]
        port = e["port"]
        if host and port:
            sub_ports.add(f"{host}:{port}")

    # Complementa com nmap (domínios resolvidos nos resultados)
    # (nmap pode ter IPs; sub_ports já vem do httpx)

    sub_ports_file = f"{outdir}/subdominios_ativos_portas.txt"
    write_lines(sub_ports_file, sorted(sub_ports))

    # ── 2. IPs com http/https (ex: http://1.2.3.4:80 ou https://1.2.3.4:443)
    ip_url_set = set()
    for e in entries:
        ip     = e["ip"]
        port   = e["port"]
        scheme = e["scheme"]
        if ip and port:
            ip_url_set.add(f"{scheme}://{ip}:{port}")

    # Complementa com nmap (hosts sem httpx confirmado)
    SSL_PORTS = {"443", "8443", "9443", "6443", "4443", "2076", "10000"}
    for ip, ports in nmap_results.items():
        for p in ports:
            scheme = "https" if p in SSL_PORTS else "http"
            ip_url_set.add(f"{scheme}://{ip}:{p}")

    ip_url_file = f"{outdir}/ips_ativos_com_protocolo.txt"
    write_lines(ip_url_file, sorted(ip_url_set))

    # ── 3. IPs + porta simples (sem protocolo) ex: 1.2.3.4:80
    ip_port_set = set()
    for entry in ip_url_set:
        # Remove scheme
        clean = re.sub(r"^https?://", "", entry)
        ip_port_set.add(clean)

    ip_port_file = f"{outdir}/ips_ativos_portas.txt"
    write_lines(ip_port_file, sorted(ip_port_set))

    # ── Resumo
    print()
    log("══════════════ RESUMO ══════════════", "OK")
    log(f"Subdomínios ativos + portas : {sub_ports_file}", "OK")
    log(f"IPs com protocolo           : {ip_url_file}", "OK")
    log(f"IPs + porta (simples)       : {ip_port_file}", "OK")

    return sub_ports_file, ip_url_file, ip_port_file


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recon automatizado: subdomínios → nmap → httpx"
    )
    parser.add_argument("domain", help="Domínio alvo (ex: exemplo.com.br)")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Diretório de saída (padrão: recon_<domain>_<timestamp>)"
    )
    parser.add_argument(
        "--skip-nmap", action="store_true",
        help="Pula o nmap (útil se já tiver subs_domain.txt)"
    )
    parser.add_argument(
        "--subs-file", default=None,
        help="Usa arquivo de subdomínios existente (pula coleta)"
    )
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = args.output or f"recon_{domain.replace('.', '_')}_{ts}"
    Path(outdir).mkdir(parents=True, exist_ok=True)

    banner()
    log(f"Alvo  : {domain}")
    log(f"Output: {outdir}")
    log(f"Portas: {PORTS}")
    print()

    check_tools()

    # 1. Subdomínios
    if args.subs_file:
        subs_file = args.subs_file
        subs = Path(subs_file).read_text().splitlines()
        log(f"Usando arquivo de subs existente: {subs_file} ({len(subs)} entradas)")
    else:
        subs_file, subs = collect_subdomains(domain, outdir)

    if not subs:
        log("Nenhum subdomínio encontrado. Encerrando.", "ERR")
        sys.exit(1)

    # 2. Nmap
    nmap_results = {}
    if not args.skip_nmap:
        nmap_results = run_nmap(subs_file, outdir)
    else:
        log("Nmap pulado (--skip-nmap)", "WARN")

    # 3. HTTPX
    alive_file, alive_json = run_httpx(subs_file, outdir)

    # 4. Parse & consolidação
    entries = parse_httpx_json(alive_json)
    log(f"HTTPX retornou {len(entries)} URLs ativas", "OK")

    build_output_files(entries, nmap_results, outdir)

    print()
    log(f"Recon finalizado! Resultados em: {outdir}/", "OK")


if __name__ == "__main__":
    main()
