#!/usr/bin/env python3
"""
favicon_recon.py

Ferramenta de reconhecimento passivo/ativo para OSINT:
  1. Enumera subdomínios de um domínio-alvo usando:
       - subfinder (binário externo, se instalado)
       - assetfinder (binário externo, se instalado)
       - AlienVault OTX (API pública)
       - crt.sh (API pública, Certificate Transparency)
  2. Para cada subdomínio/host único encontrado, tenta baixar o favicon.ico
     (via http e https).
  3. Calcula o hash mmh3 (o mesmo algoritmo usado pelo Shodan) do favicon
     em base64.
  4. Deduplica os hashes e mostra, para cada hash ÚNICO (não repetido em
     mais de um host), a query pronta para pesquisar no Shodan.

Requisitos:
  pip install requests mmh3 --break-system-packages

  Opcionais (para os módulos ativos de enumeração):
    - subfinder: https://github.com/projectdiscovery/subfinder
    - assetfinder: https://github.com/tomnomnom/assetfinder

Uso:
  python3 favicon_recon.py -d exemplo.com.br
  python3 favicon_recon.py -d exemplo.com.br --timeout 8 --workers 20
  python3 favicon_recon.py -d exemplo.com.br --skip-subfinder --skip-assetfinder

Aviso legal:
  Use apenas em domínios que você possui ou tem autorização explícita
  para testar (pentest / bug bounty com escopo definido). A enumeração
  via APIs públicas (OTX, crt.sh) é passiva. A coleta de favicon.ico faz
  requisições HTTP diretas aos hosts encontrados — isso já é reconhecimento
  ativo, ainda que de baixíssimo impacto.
"""

import argparse
import base64
import concurrent.futures
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

import requests

try:
    import mmh3
except ImportError:
    print("[!] Módulo 'mmh3' não encontrado. Instale com:")
    print("    pip install mmh3 --break-system-packages")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Estruturas de dados
# --------------------------------------------------------------------------- #

@dataclass
class FaviconResult:
    host: str
    url: str
    hash_value: Optional[int] = None
    size_bytes: int = 0
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Enumeração de subdomínios
# --------------------------------------------------------------------------- #

def run_subfinder(domain: str, timeout: int = 60) -> set:
    """Executa o subfinder (se instalado) e retorna um set de subdomínios."""
    if not shutil.which("subfinder"):
        print("[i] subfinder não encontrado no PATH — pulando.")
        return set()

    print("[*] Rodando subfinder...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        subs = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        print(f"[+] subfinder encontrou {len(subs)} subdomínios.")
        return subs
    except subprocess.TimeoutExpired:
        print("[!] subfinder excedeu o tempo limite.")
        return set()
    except Exception as e:
        print(f"[!] Erro ao rodar subfinder: {e}")
        return set()


def run_assetfinder(domain: str, timeout: int = 60) -> set:
    """Executa o assetfinder (se instalado) e retorna um set de subdomínios."""
    if not shutil.which("assetfinder"):
        print("[i] assetfinder não encontrado no PATH — pulando.")
        return set()

    print("[*] Rodando assetfinder...")
    try:
        result = subprocess.run(
            ["assetfinder", "--subs-only", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        subs = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        print(f"[+] assetfinder encontrou {len(subs)} subdomínios.")
        return subs
    except subprocess.TimeoutExpired:
        print("[!] assetfinder excedeu o tempo limite.")
        return set()
    except Exception as e:
        print(f"[!] Erro ao rodar assetfinder: {e}")
        return set()


def run_otx(domain: str, timeout: int = 20) -> set:
    """Consulta a API pública do AlienVault OTX."""
    print("[*] Consultando AlienVault OTX...")
    subs = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname")
                if hostname and domain in hostname:
                    subs.add(hostname.lower())
        print(f"[+] OTX encontrou {len(subs)} subdomínios.")
    except Exception as e:
        print(f"[!] Erro ao consultar OTX: {e}")
    return subs


def run_crtsh(domain: str, timeout: int = 30) -> set:
    """Consulta a API pública do crt.sh (Certificate Transparency)."""
    print("[*] Consultando crt.sh...")
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                # crt.sh às vezes retorna JSON malformado / múltiplos objetos
                text = resp.text.strip()
                data = []
                for line in text.replace("}{", "}\n{").splitlines():
                    try:
                        import json
                        data.append(json.loads(line))
                    except Exception:
                        continue
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and domain in name:
                        subs.add(name)
        print(f"[+] crt.sh encontrou {len(subs)} subdomínios.")
    except Exception as e:
        print(f"[!] Erro ao consultar crt.sh: {e}")
    return subs


# --------------------------------------------------------------------------- #
# Coleta e hash de favicon
# --------------------------------------------------------------------------- #

def compute_mmh3_favicon_hash(content: bytes) -> int:
    """Calcula o hash mmh3 no mesmo formato que o Shodan usa (base64 + mmh3)."""
    b64 = base64.encodebytes(content)
    return mmh3.hash(b64)


def fetch_favicon(host: str, timeout: int = 8) -> FaviconResult:
    """
    Tenta baixar o favicon.ico de um host, testando https e http.
    Retorna um FaviconResult com o hash calculado (ou erro).
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        )
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/favicon.ico"
        try:
            resp = requests.get(
                url, timeout=timeout, headers=headers, verify=False, allow_redirects=True
            )
            if resp.status_code == 200 and resp.content and len(resp.content) > 0:
                h = compute_mmh3_favicon_hash(resp.content)
                return FaviconResult(
                    host=host, url=url, hash_value=h, size_bytes=len(resp.content)
                )
        except requests.exceptions.RequestException as e:
            last_error = str(e)
            continue

    return FaviconResult(host=host, url=f"https://{host}/favicon.ico", error="não encontrado / sem resposta")


def collect_favicons(hosts: set, workers: int = 15, timeout: int = 8) -> list:
    """Coleta favicons de todos os hosts em paralelo."""
    print(f"\n[*] Coletando favicon.ico de {len(hosts)} hosts (workers={workers})...\n")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(fetch_favicon, host, timeout): host for host in hosts
        }
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            res = future.result()
            status = f"hash={res.hash_value}" if res.hash_value is not None else f"erro: {res.error}"
            print(f"  [{i}/{len(hosts)}] {res.host:<45} -> {status}")
            results.append(res)
    return results


# --------------------------------------------------------------------------- #
# Análise / deduplicação de hashes
# --------------------------------------------------------------------------- #

def analyze_hashes(results: list):
    """
    Agrupa os resultados por hash. Mostra:
      - hashes ÚNICOS (aparecem em apenas 1 host) -> mais interessantes,
        pois indicam favicon customizado, não genérico.
      - hashes repetidos (aparecem em vários hosts) -> favicon compartilhado
        entre múltiplos hosts (pode indicar mesma aplicação/infra).
    """
    from collections import defaultdict

    by_hash = defaultdict(list)
    for r in results:
        if r.hash_value is not None:
            by_hash[r.hash_value].append(r)

    unique_hashes = {h: hosts for h, hosts in by_hash.items() if len(hosts) == 1}
    shared_hashes = {h: hosts for h, hosts in by_hash.items() if len(hosts) > 1}

    return unique_hashes, shared_hashes


def print_shodan_queries(unique_hashes: dict, shared_hashes: dict):
    print("\n" + "=" * 70)
    print(" RESULTADO — QUERIES PRONTAS PARA O SHODAN")
    print("=" * 70)

    if shared_hashes:
        print("\n--- Hashes REPETIDOS (mesmo favicon em vários hosts do próprio alvo) ---")
        for h, hosts in shared_hashes.items():
            print(f"\n  Hash: {h}")
            for r in hosts:
                print(f"    - {r.url}")
            print(f"  Shodan: http.favicon.hash:{h}")

    if unique_hashes:
        print("\n--- Hashes ÚNICOS (favicon exclusivo daquele host — mais promissores) ---")
        for h, hosts in unique_hashes.items():
            r = hosts[0]
            print(f"\n  Host: {r.host}")
            print(f"  URL : {r.url}")
            print(f"  Hash: {h}")
            print(f"  Shodan: http.favicon.hash:{h}")
    else:
        print("\n[i] Nenhum hash único encontrado.")

    print("\n" + "=" * 70)
    print(" Dica: cole a query 'http.favicon.hash:<numero>' na busca do Shodan")
    print(" (shodan.io) ou via CLI: shodan search 'http.favicon.hash:<numero>'")
    print("=" * 70 + "\n")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Enumeração de subdomínios + favicon hashing para pesquisa no Shodan."
    )
    parser.add_argument("-d", "--domain", required=True, help="Domínio alvo (ex: exemplo.com.br)")
    parser.add_argument("--workers", type=int, default=15, help="Threads paralelas para coleta de favicon")
    parser.add_argument("--timeout", type=int, default=8, help="Timeout (segundos) por requisição de favicon")
    parser.add_argument("--skip-subfinder", action="store_true", help="Não rodar subfinder")
    parser.add_argument("--skip-assetfinder", action="store_true", help="Não rodar assetfinder")
    parser.add_argument("--skip-otx", action="store_true", help="Não consultar OTX")
    parser.add_argument("--skip-crtsh", action="store_true", help="Não consultar crt.sh")
    parser.add_argument(
        "--include-root",
        action="store_true",
        help="Também tenta o domínio raiz (sem subdomínio) na coleta de favicon",
    )
    args = parser.parse_args()

    # Silencia warning de verify=False do requests (autoassinados são comuns em intranets)
    requests.packages.urllib3.disable_warnings()

    domain = args.domain.strip().lower()
    print(f"\n[*] Alvo: {domain}\n")

    all_subs = set()

    if not args.skip_subfinder:
        all_subs |= run_subfinder(domain)
    if not args.skip_assetfinder:
        all_subs |= run_assetfinder(domain)
    if not args.skip_otx:
        all_subs |= run_otx(domain)
    if not args.skip_crtsh:
        all_subs |= run_crtsh(domain)

    if args.include_root:
        all_subs.add(domain)
        all_subs.add(f"www.{domain}")

    # Limpeza básica
    all_subs = {s.strip().strip(".").lower() for s in all_subs if s.strip()}

    print(f"\n[+] Total de hosts únicos combinando todas as fontes: {len(all_subs)}")
    if not all_subs:
        print("[!] Nenhum subdomínio encontrado. Encerrando.")
        sys.exit(0)

    for s in sorted(all_subs):
        print(f"    - {s}")

    results = collect_favicons(all_subs, workers=args.workers, timeout=args.timeout)

    ok = [r for r in results if r.hash_value is not None]
    fail = [r for r in results if r.hash_value is None]

    print(f"\n[+] Favicons coletados com sucesso: {len(ok)}")
    print(f"[i] Hosts sem favicon acessível: {len(fail)}")

    unique_hashes, shared_hashes = analyze_hashes(results)
    print_shodan_queries(unique_hashes, shared_hashes)


if __name__ == "__main__":
    main()
